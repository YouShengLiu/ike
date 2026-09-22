package eap

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

// Inner Diameter AVP codes carried in the EAP-TTLS tunnel (RFC 5281 §11, PAP).
const (
	avpCodeUserName     uint32 = 1
	avpCodeUserPassword uint32 = 2
)

const (
	avpFlagVendor    byte = 0x80
	avpFlagMandatory byte = 0x40
	avpHeaderLen          = 8 // no vendor id
)

// PapCredential holds the cleartext PAP inner identity/password.
type PapCredential struct {
	UserName     []byte
	UserPassword []byte
}

// ParsePapAVPs scans a decrypted inner AVP stream and extracts the PAP
// User-Name and User-Password AVPs. Vendor-specific AVPs are skipped.
func ParsePapAVPs(b []byte) (*PapCredential, error) {
	cred := &PapCredential{}
	pos := 0
	for pos+avpHeaderLen <= len(b) {
		code := binary.BigEndian.Uint32(b[pos : pos+4])
		flags := b[pos+4]
		length := int(b[pos+5])<<16 | int(b[pos+6])<<8 | int(b[pos+7])
		if length < avpHeaderLen || pos+length > len(b) {
			return nil, errors.Errorf("ParsePapAVPs: bad AVP length %d at pos %d", length, pos)
		}
		dataStart := pos + avpHeaderLen
		if flags&avpFlagVendor != 0 {
			// Vendor AVP has an extra 4-byte Vendor-Id; skip its data wholesale.
			dataStart += 4
		}
		if dataStart > pos+length {
			return nil, errors.Errorf("ParsePapAVPs: header overruns AVP length at pos %d", pos)
		}
		data := b[dataStart : pos+length]
		if flags&avpFlagVendor == 0 {
			switch code {
			case avpCodeUserName:
				cred.UserName = append([]byte(nil), data...)
			case avpCodeUserPassword:
				// RFC 5281 §11.2.2: the PAP password is zero-padded to a
				// 16-octet boundary to obfuscate its length, and the AVP
				// Length counts the padding. Strip trailing NULs to recover
				// the cleartext (a text password never ends in NUL).
				cred.UserPassword = append([]byte(nil), bytes.TrimRight(data, "\x00")...)
			}
		}
		// Advance to next 4-byte-aligned AVP.
		pos += length
		for pos%4 != 0 {
			pos++
		}
	}
	if cred.UserName == nil || cred.UserPassword == nil {
		return nil, errors.Errorf("ParsePapAVPs: missing User-Name or User-Password AVP")
	}
	return cred, nil
}
