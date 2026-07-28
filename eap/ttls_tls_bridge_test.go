package eap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// ---- shared test helpers (also usable by Task 4/5 tests) ----

// generateSelfSignedCert builds a throwaway ECDSA self-signed certificate
// for use as a tls.Config server certificate in tests.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "eap-ttls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// testTLSServerConfig returns a self-signed server config for tests.
func testTLSServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert := generateSelfSignedCert(t)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// testTLSClientConfig returns a client config that trusts exactly the given
// self-signed server config's certificate, so tests exercise real chain
// verification instead of disabling it via InsecureSkipVerify.
func testTLSClientConfig(t *testing.T, serverCfg *tls.Config) *tls.Config {
	t.Helper()
	leaf, err := x509.ParseCertificate(serverCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

// memBuf is a goroutine-safe, unbounded byte buffer with a blocking Read,
// used to build simple in-memory net.Conn-like endpoints for tests.
type memBuf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newMemBuf() *memBuf {
	b := &memBuf{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *memBuf) write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := b.buf.Write(p)
	b.cond.Broadcast()
	return n, err
}

// read blocks until at least one byte is available, or the buffer is closed.
func (b *memBuf) read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.buf.Len() == 0 && !b.closed {
		b.cond.Wait()
	}
	if b.buf.Len() == 0 && b.closed {
		return 0, io.EOF
	}
	return b.buf.Read(p)
}

// readAvailable drains and returns whatever bytes are currently buffered,
// without blocking. Returns nil if nothing is available.
func (b *memBuf) readAvailable() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() == 0 {
		return nil
	}
	out := append([]byte(nil), b.buf.Bytes()...)
	b.buf.Reset()
	return out
}

func (b *memBuf) close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.cond.Broadcast()
	return nil
}

// memConn is a minimal net.Conn backed by two memBuf pipes (one per direction).
type memConn struct {
	readBuf  *memBuf
	writeBuf *memBuf
}

func (c *memConn) Read(p []byte) (int, error)  { return c.readBuf.read(p) }
func (c *memConn) Write(p []byte) (int, error) { return c.writeBuf.write(p) }
func (c *memConn) Close() error {
	return c.writeBuf.close()
}
func (c *memConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *memConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "mem" }
func (fakeAddr) String() string  { return "mem" }

// feedConn is the test-side handle for the non-client end of a memConn pair:
// it lets the test shuttle bytes to/from a real tls.Client without a second
// full TLS stack.
type feedConn struct {
	toClient *memBuf // bridge/test writes here, client reads
	toServer *memBuf // client writes here, bridge/test reads
}

func (f *feedConn) writeToClient(p []byte) error {
	_, err := f.toClient.write(p)
	return err
}

// readFromClient drains whatever the client has written so far, without blocking.
func (f *feedConn) readFromClient() []byte {
	return f.toServer.readAvailable()
}

// newMemConnPair returns a net.Conn suitable for tls.Client, and a feedConn
// handle the test uses to shuttle bytes between that client and the bridge.
func newMemConnPair() (net.Conn, *feedConn) {
	toClient := newMemBuf()
	toServer := newMemBuf()
	client := &memConn{readBuf: toClient, writeBuf: toServer}
	feed := &feedConn{toClient: toClient, toServer: toServer}
	return client, feed
}

// ---- tests ----

func TestTLSBridgeHandshakeWithRealClient(t *testing.T) {
	serverCfg := testTLSServerConfig(t)
	bridge := newTLSBridge(serverCfg)
	defer func() {
		if err := bridge.close(); err != nil {
			t.Logf("bridge close: %v", err)
		}
	}()

	// A real tls.Client on the other end, connected via an in-memory conn pair.
	clientConn, serverFeed := newMemConnPair()
	clientCfg := testTLSClientConfig(t, serverCfg)
	client := tls.Client(clientConn, clientCfg)

	done := make(chan error, 1)
	go func() { done <- client.HandshakeContext(context.Background()) }()

	// Shuttle bytes between the real client and the bridge. Note: we pump
	// until the *client* reports completion, not until bridge.handshakeDone()
	// flips true. The server's final flight (ChangeCipherSpec+Finished) is
	// written to the bridge's outbound buffer synchronously, just before its
	// Handshake() call returns and hsDone is set -- so a naive
	// "for !bridge.handshakeDone() { pump }" loop can observe hsDone==true
	// and exit without ever draining that last flight to the client.
	deadline := time.After(5 * time.Second)
	var clientErr error
pump:
	for {
		if out := bridge.readOutbound(); len(out) > 0 {
			if err := serverFeed.writeToClient(out); err != nil {
				t.Fatalf("writeToClient: %v", err)
			}
		}
		if in := serverFeed.readFromClient(); len(in) > 0 {
			if err := bridge.writeInbound(in); err != nil {
				t.Fatalf("writeInbound: %v", err)
			}
		}
		select {
		case clientErr = <-done:
			break pump
		case <-deadline:
			t.Fatal("handshake timed out")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if clientErr != nil {
		t.Fatalf("client handshake failed: %v", clientErr)
	}

	// The bridge's own Handshake() call returns essentially in lock-step
	// with producing that final flight, so it should already be done; allow
	// a brief grace period for the goroutine to update hsDone.
	waitDeadline := time.After(time.Second)
	for !bridge.handshakeDone() {
		select {
		case <-waitDeadline:
			t.Fatal("bridge did not observe handshake completion")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := bridge.handshakeErr(); err != nil {
		t.Fatalf("bridge handshake failed: %v", err)
	}

	if bridge.connState().Version == 0 {
		t.Fatal("bridge reports no negotiated TLS version")
	}
}

func TestTLSBridgeApplicationDataRoundTrip(t *testing.T) {
	serverCfg := testTLSServerConfig(t)
	bridge := newTLSBridge(serverCfg)
	defer func() {
		if err := bridge.close(); err != nil {
			t.Logf("bridge close: %v", err)
		}
	}()

	clientConn, serverFeed := newMemConnPair()
	clientCfg := testTLSClientConfig(t, serverCfg)
	client := tls.Client(clientConn, clientCfg)

	hsDone := make(chan error, 1)
	go func() { hsDone <- client.HandshakeContext(context.Background()) }()

	// See TestTLSBridgeHandshakeWithRealClient for why we pump until the
	// client reports completion rather than until bridge.handshakeDone().
	deadline := time.After(5 * time.Second)
pump:
	for {
		if out := bridge.readOutbound(); len(out) > 0 {
			if err := serverFeed.writeToClient(out); err != nil {
				t.Fatalf("writeToClient: %v", err)
			}
		}
		if in := serverFeed.readFromClient(); len(in) > 0 {
			if err := bridge.writeInbound(in); err != nil {
				t.Fatalf("writeInbound: %v", err)
			}
		}
		select {
		case err := <-hsDone:
			if err != nil {
				t.Fatalf("client handshake failed: %v", err)
			}
			break pump
		case <-deadline:
			t.Fatal("handshake timed out")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	// Client sends application data through the tunnel to the bridge.
	appWriteDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello inner AVP"))
		appWriteDone <- err
	}()

	var got []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		readDeadline := time.After(5 * time.Second)
		for {
			select {
			case <-readDeadline:
				return
			default:
			}
			if out := bridge.readOutbound(); len(out) > 0 {
				if err := serverFeed.writeToClient(out); err != nil {
					return
				}
			}
			// Only attempt to read decrypted app data right after feeding a
			// complete inbound chunk: readAppData blocks until the engine has
			// something to decrypt, so calling it with nothing in flight
			// would hang this goroutine forever.
			if in := serverFeed.readFromClient(); len(in) > 0 {
				if err := bridge.writeInbound(in); err != nil {
					return
				}
				data, err := bridge.readAppData()
				if len(data) > 0 {
					got = append(got, data...)
				}
				if err != nil && !errors.Is(err, io.EOF) {
					return
				}
				if len(got) > 0 {
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	if err := <-appWriteDone; err != nil {
		t.Fatalf("client write: %v", err)
	}
	<-readDone

	if string(got) != "hello inner AVP" {
		t.Fatalf("readAppData = %q, want %q", got, "hello inner AVP")
	}
}
