package eap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// encodeVendorAVP builds one vendor-specific Diameter AVP (V flag set, with
// a 4-byte Vendor-Id ahead of data), padded to a 4-byte boundary. Unlike
// encodeAVP (Task 2's non-vendor helper), this is test-only scaffolding for
// proving ParsePapAVPs correctly skips vendor AVPs rather than misreading
// their Vendor-Id-prefixed data as a plain User-Name/User-Password value.
func encodeVendorAVP(code, vendorID uint32, data []byte) []byte {
	length := avpHeaderLen + 4 + len(data)
	out := make([]byte, avpHeaderLen)
	binary.BigEndian.PutUint32(out[0:4], code)
	out[4] = avpFlagVendor
	out[5] = byte(length >> 16)
	out[6] = byte(length >> 8)
	out[7] = byte(length)
	vid := make([]byte, 4)
	binary.BigEndian.PutUint32(vid, vendorID)
	out = append(out, vid...)
	out = append(out, data...)
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}
	return out
}

func TestEncodeAVPPaddingAndLength(t *testing.T) {
	// User-Name = "ab" (2 bytes) → header 8 + data 2 = length 10, padded to 12.
	got := encodeAVP(avpCodeUserName, true, []byte("ab"))
	want := []byte{
		0x00, 0x00, 0x00, 0x01, // code = 1
		0x40, 0x00, 0x00, 0x0a, // flags M=0x40, length = 10
		'a', 'b', 0x00, 0x00, // data + 2 pad
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeAVP = %x, want %x", got, want)
	}
}

func TestParsePapAVPsRoundTrip(t *testing.T) {
	buf := append(encodeAVP(avpCodeUserName, true, []byte("alice")),
		encodeAVP(avpCodeUserPassword, true, []byte("s3cret"))...)
	cred, err := ParsePapAVPs(buf)
	if err != nil {
		t.Fatalf("ParsePapAVPs error = %v", err)
	}
	if string(cred.UserName) != "alice" || string(cred.UserPassword) != "s3cret" {
		t.Fatalf("got name=%q pass=%q", cred.UserName, cred.UserPassword)
	}
}

func TestParsePapAVPsMissingPassword(t *testing.T) {
	buf := encodeAVP(avpCodeUserName, true, []byte("alice"))
	if _, err := ParsePapAVPs(buf); err == nil {
		t.Fatal("expected error when User-Password AVP absent")
	}
}

// TestParsePapAVPsMissingUserName is the mirror of
// TestParsePapAVPsMissingPassword: User-Password present, User-Name absent.
func TestParsePapAVPsMissingUserName(t *testing.T) {
	buf := encodeAVP(avpCodeUserPassword, true, []byte("s3cret"))
	if _, err := ParsePapAVPs(buf); err == nil {
		t.Fatal("expected error when User-Name AVP absent")
	}
}

// TestParsePapAVPsSkipsVendorAVP proves a vendor-specific AVP (V flag set,
// with a Vendor-Id) is skipped wholesale rather than misread as a plain
// User-Name/User-Password value -- even when it reuses the User-Name AVP
// code, its Vendor-Id-prefixed data must never end up in cred.UserName.
func TestParsePapAVPsSkipsVendorAVP(t *testing.T) {
	buf := append(encodeVendorAVP(avpCodeUserName, 10415, []byte("trap")),
		append(encodeAVP(avpCodeUserName, true, []byte("alice")),
			encodeAVP(avpCodeUserPassword, true, []byte("s3cret"))...)...)
	cred, err := ParsePapAVPs(buf)
	if err != nil {
		t.Fatalf("ParsePapAVPs error = %v", err)
	}
	if string(cred.UserName) != "alice" || string(cred.UserPassword) != "s3cret" {
		t.Fatalf("got name=%q pass=%q, vendor AVP was misparsed", cred.UserName, cred.UserPassword)
	}
}

// TestParsePapAVPsRejectsBadLength covers the length < avpHeaderLen and
// pos+length > len(b) guards (ttls_avp.go:56): AVP framing that is either
// self-declared shorter than the minimum header, or claims more bytes than
// the buffer actually has. Both are attacker-influenceable since this
// parses decrypted-but-untrusted inner tunnel data.
func TestParsePapAVPsRejectsBadLength(t *testing.T) {
	tests := map[string][]byte{
		"length below minimum header": {
			0x00, 0x00, 0x00, 0x01, // code = 1 (User-Name)
			0x40, 0x00, 0x00, 0x04, // flags=M, length = 4 (< avpHeaderLen of 8)
		},
		"length exceeds buffer": {
			0x00, 0x00, 0x00, 0x01, // code = 1 (User-Name)
			0x40, 0x00, 0x00, 0x14, // flags=M, length = 20, but buffer only has 8 bytes
		},
	}
	for name, buf := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePapAVPs(buf); err == nil {
				t.Fatal("expected error for malformed AVP length")
			}
		})
	}
}

// TestParsePapAVPsRejectsShortVendorAVP covers the dataStart > pos+length
// guard (ttls_avp.go:64): a vendor AVP (V flag set) whose declared length
// is long enough to pass the buffer-bounds check but too short to actually
// hold the 4-byte Vendor-Id the V flag promises.
func TestParsePapAVPsRejectsShortVendorAVP(t *testing.T) {
	buf := []byte{
		0x00, 0x00, 0x00, 0x01, // code = 1 (User-Name)
		0x80, 0x00, 0x00, 0x0a, // flags=V, length = 10 (header 8 + only 2 bytes, not enough for a 4-byte Vendor-Id)
		0xaa, 0xbb,
	}
	if _, err := ParsePapAVPs(buf); err == nil {
		t.Fatal("expected error when vendor AVP length can't hold its Vendor-Id")
	}
}
