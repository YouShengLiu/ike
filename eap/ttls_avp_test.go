package eap

import (
	"bytes"
	"testing"
)

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
