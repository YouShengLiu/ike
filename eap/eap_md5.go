package eap

import (
	"github.com/pkg/errors"
)

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Value-Size   |  Value ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Name ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// EapMD5 corresponds to EAP Type 4 (MD5-Challenge)
// RFC 3748 Section 5.4
var _ EapTypeData = &EapMD5{}

const (
	EapMD5ChallengeSize = 16 // MD5 challenge is always 16 bytes
	EapMD5HeaderLen     = 2  // 1 byte Type + 1 byte ValueSize
	EapMD5MinLen        = 3  // 1 byte Type + 1 byte ValueSize + at least 1 byte Value (but spec requires 16)
)

type EapMD5 struct {
	ValueSize uint8  // Value-Size field (should be 16 for MD5)
	Value     []byte // MD5-Challenge value (16 bytes)
	Name      string // Optional Name field (variable length)
}

func (e *EapMD5) Type() EapType {
	return EapTypeMD5
}

func (e *EapMD5) Marshal() ([]byte, error) {
	if e.ValueSize != EapMD5ChallengeSize {
		return nil, errors.New("EapMD5: ValueSize must be 16")
	}
	if len(e.Value) != EapMD5ChallengeSize {
		return nil, errors.Errorf("EapMD5: Value must be %d bytes, got %d", EapMD5ChallengeSize, len(e.Value))
	}

	data := []byte{byte(EapTypeMD5), e.ValueSize}
	data = append(data, e.Value...)
	if len(e.Name) > 0 {
		data = append(data, []byte(e.Name)...)
	}
	return data, nil
}

func (e *EapMD5) Unmarshal(b []byte) error {
	if len(b) < EapMD5MinLen {
		return errors.New("EapMD5: not enough data")
	}
	actualType := EapType(b[0])
	if actualType != EapTypeMD5 {
		return errors.Errorf("EapMD5: expect type %s but got %s", EapTypeMD5.String(), actualType.String())
	}

	e.ValueSize = b[1]
	if e.ValueSize != EapMD5ChallengeSize {
		return errors.Errorf("EapMD5: ValueSize must be %d, got %d", EapMD5ChallengeSize, e.ValueSize)
	}
	if len(b) < EapMD5HeaderLen+int(e.ValueSize) {
		return errors.Errorf(
			"EapMD5: insufficient data, expected at least %d bytes, got %d",
			EapMD5HeaderLen+int(e.ValueSize), len(b),
		)
	}

	e.Value = make([]byte, EapMD5ChallengeSize)
	copy(e.Value, b[EapMD5HeaderLen:EapMD5HeaderLen+EapMD5ChallengeSize])

	if len(b) > EapMD5HeaderLen+EapMD5ChallengeSize {
		e.Name = string(b[EapMD5HeaderLen+EapMD5ChallengeSize:])
	} else {
		e.Name = ""
	}
	return nil
}

func (e *EapMD5) SetChallengeValue(value []byte) error {
	if len(value) != EapMD5ChallengeSize {
		return errors.Errorf("EapMD5: challenge value must be %d bytes, got %d", EapMD5ChallengeSize, len(value))
	}
	e.ValueSize = EapMD5ChallengeSize
	e.Value = make([]byte, EapMD5ChallengeSize)
	copy(e.Value, value)
	return nil
}

func (e *EapMD5) SetName(name string) {
	e.Name = name
}
