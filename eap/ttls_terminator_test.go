package eap

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// TestTerminatorFullPapFlow drives a full EAP-TTLS authentication (TTLS-Start
// -> TLS handshake -> tunneled PAP AVPs) against a real tls.Client, using an
// MTU large enough that no fragmentation is needed.
func TestTerminatorFullPapFlow(t *testing.T) {
	srvCfg := testTLSServerConfig(t)
	term := NewTerminator(srvCfg, 1000)

	start, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(start.OutTypeData) < 2 || start.OutTypeData[1]&EapTlsFlagStart == 0 {
		t.Fatal("first packet must have Start flag")
	}

	cred, keys := runTtlsPeer(t, term, start, "alice", "s3cret", 5*time.Second)
	if string(cred.UserName) != "alice" || string(cred.UserPassword) != "s3cret" {
		t.Fatalf("got name=%q pass=%q", cred.UserName, cred.UserPassword)
	}
	if len(keys.MSK) != 64 {
		t.Fatalf("MSK len = %d, want 64", len(keys.MSK))
	}
	if len(keys.EMSK) != 64 {
		t.Fatalf("EMSK len = %d, want 64", len(keys.EMSK))
	}
}

// TestTerminatorFullPapFlowSmallMTU forces multi-fragment flights in BOTH
// directions (server handshake flight out, and the peer's own flights in),
// proving emitOutbound's fragmentation and Process's reassembly are correct,
// not just adequate for single-packet flows.
func TestTerminatorFullPapFlowSmallMTU(t *testing.T) {
	srvCfg := testTLSServerConfig(t)
	term := NewTerminator(srvCfg, 200)

	start, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	cred, keys := runTtlsPeer(t, term, start, "alice", "s3cret", 5*time.Second)
	if string(cred.UserName) != "alice" || string(cred.UserPassword) != "s3cret" {
		t.Fatalf("got name=%q pass=%q", cred.UserName, cred.UserPassword)
	}
	if len(keys.MSK) != 64 {
		t.Fatalf("MSK len = %d, want 64", len(keys.MSK))
	}
}

// runTtlsPeer is a test harness that plays the EAP-TTLS peer (supplicant)
// role: it drives a real tls.Client through the Terminator's Process calls
// (including EAP-layer fragmentation in both directions), completes the TLS
// handshake, then writes PAP inner AVPs (User-Name + User-Password) into the
// tunnel, looping term.Process until it reports Done. It returns the
// extracted credential and keys, failing the test on any error or timeout.
func runTtlsPeer(t *testing.T, term *Terminator, start *TerminatorStep, username, password string, timeout time.Duration) (*PapCredential, *TtlsKeys) {
	t.Helper()

	// term.cfg/term.mtu are accessed directly since this harness lives in
	// the same package -- it needs a client config that trusts the same
	// self-signed cert the terminator's server config presents, and a peer
	// MTU to fragment its own output at (using the terminator's own MTU
	// keeps both directions symmetric for the small-MTU test).
	clientCfg := testTLSClientConfig(t, term.cfg)
	clientConn, feed := newMemConnPair()
	client := tls.Client(clientConn, clientCfg)
	peerMTU := term.mtu

	hsDone := make(chan error, 1)
	go func() { hsDone <- client.HandshakeContext(context.Background()) }()

	writeDone := make(chan error, 1)
	handshakeChecked := false
	writeStarted := false

	deadline := time.Now().Add(timeout)

	// pendingToServer holds the remaining bytes of the client's own
	// outbound message currently being fragmented to the server. Symmetric
	// to Terminator.outPending: non-nil/non-empty means the terminator's
	// next reply is expected to just be its own fragment-continuation, not
	// something requiring us to fetch fresh client bytes.
	var pendingToServer []byte

	step := start
	for {
		if step.Done {
			if !step.Success {
				t.Fatalf("terminator reported failure")
			}
			return step.Cred, step.Keys
		}

		var pkt EapTtls
		if err := pkt.Unmarshal(step.OutTypeData); err != nil {
			t.Fatalf("unmarshal server output: %v", err)
		}
		// The underlying transport to the real tls.Client is a plain byte
		// stream (memConn), so fragment boundaries on the server->client
		// direction don't need to be preserved beyond delivering the bytes
		// in order -- the client's TLS engine just reads a continuous
		// stream regardless of how the server chopped it into EAP packets.
		if len(pkt.TLSData) > 0 {
			if err := feed.writeToClient(pkt.TLSData); err != nil {
				t.Fatalf("writeToClient: %v", err)
			}
		}

		var inTypeData []byte
		switch {
		case pkt.Flags&EapTlsFlagMoreFragments != 0:
			// Server sent a non-final fragment; ack it to request the next
			// one. No client bytes are consumed for this round.
			ack := &EapTtls{}
			out, err := ack.Marshal()
			if err != nil {
				t.Fatalf("marshal ack: %v", err)
			}
			inTypeData = out

		case len(pendingToServer) > 0:
			// Continue fragmenting out the client's in-flight message.
			inTypeData = nextClientFragment(t, &pendingToServer, peerMTU)

		default:
			raw := waitForClientBytes(t, feed, hsDone, writeDone, &handshakeChecked, &writeStarted, client, username, password, deadline)
			pendingToServer = raw
			inTypeData = nextClientFragment(t, &pendingToServer, peerMTU)
		}

		next, err := term.Process(inTypeData)
		if err != nil {
			t.Fatalf("term.Process: %v", err)
		}
		step = next
	}
}

// nextClientFragment pops up to mtu bytes off the front of *pending,
// building one EAP-TTLS packet with the M flag set iff bytes remain
// afterwards.
func nextClientFragment(t *testing.T, pending *[]byte, mtu int) []byte {
	t.Helper()
	out := &EapTtls{}
	if mtu > 0 && len(*pending) > mtu {
		out.TLSData = (*pending)[:mtu]
		*pending = (*pending)[mtu:]
		out.Flags |= EapTlsFlagMoreFragments
	} else {
		out.TLSData = *pending
		*pending = nil
	}
	b, err := out.Marshal()
	if err != nil {
		t.Fatalf("marshal client fragment: %v", err)
	}
	return b
}

// waitForClientBytes polls the feed for TLS bytes the real tls.Client has
// produced (handshake flights, or the post-handshake AVP write), kicking off
// the AVP write once the handshake has completed. It deliberately never
// calls term.Process itself: doing so before the corresponding TLS record
// has been fully delivered is exactly the sequencing hazard Task 3 flagged
// for readAppData (it blocks, so calling it too early deadlocks).
func waitForClientBytes(t *testing.T, feed *feedConn, hsDone, writeDone chan error, handshakeChecked, writeStarted *bool, client *tls.Conn, username, password string, deadline time.Time) []byte {
	t.Helper()
	for {
		if raw := feed.readFromClient(); len(raw) > 0 {
			return raw
		}
		if !*handshakeChecked {
			select {
			case err := <-hsDone:
				if err != nil {
					t.Fatalf("client handshake failed: %v", err)
				}
				*handshakeChecked = true
			default:
			}
		}
		if *handshakeChecked && !*writeStarted {
			*writeStarted = true
			payload := append(
				encodeAVP(avpCodeUserName, true, []byte(username)),
				encodeAVP(avpCodeUserPassword, true, []byte(password))...)
			go func() {
				_, err := client.Write(payload)
				writeDone <- err
			}()
		}
		select {
		case err := <-writeDone:
			if err != nil {
				t.Fatalf("client write failed: %v", err)
			}
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("waitForClientBytes: timed out waiting for client output")
		}
		time.Sleep(time.Millisecond)
	}
}
