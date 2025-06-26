package eap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validMD5Challenge = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	validMD5Name = "testuser"
	validEapMD5  = EapMD5{
		ValueSize: EapMD5ChallengeSize,
		Value:     validMD5Challenge,
		Name:      validMD5Name,
	}
	validEapMD5Bytes = append(
		append(
			[]byte{byte(EapTypeMD5), EapMD5ChallengeSize},
			validMD5Challenge...,
		),
		[]byte(validMD5Name)...,
	)
)

func TestEapMD5Marshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         EapMD5
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "ValueSize not 16",
			eap:         EapMD5{ValueSize: 15, Value: make([]byte, 15)},
			expErr:      true,
		},
		{
			description: "Value length not 16",
			eap:         EapMD5{ValueSize: 16, Value: make([]byte, 15)},
			expErr:      true,
		},
		{
			description: "Valid Marshal",
			eap:         validEapMD5,
			expMarshal:  validEapMD5Bytes,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.Marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestEapMD5Unmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expEap      EapMD5
		expErr      bool
	}{
		{
			description: "Not enough data",
			b:           []byte{byte(EapTypeMD5), 16},
			expErr:      true,
		},
		{
			description: "Wrong type",
			b:           append([]byte{0x00}, make([]byte, 17)...),
			expErr:      true,
		},
		{
			description: "ValueSize not 16",
			b:           append([]byte{byte(EapTypeMD5), 15}, make([]byte, 15)...),
			expErr:      true,
		},
		{
			description: "Insufficient data for challenge",
			b:           append([]byte{byte(EapTypeMD5), 16}, make([]byte, 10)...), // only 10 bytes for challenge
			expErr:      true,
		},
		{
			description: "Valid Unmarshal",
			b:           validEapMD5Bytes,
			expEap:      validEapMD5,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap EapMD5
			err := eap.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expEap.ValueSize, eap.ValueSize)
				require.Equal(t, tc.expEap.Value, eap.Value)
				require.Equal(t, tc.expEap.Name, eap.Name)
			}
		})
	}
}

func TestEapMD5SetChallengeValue(t *testing.T) {
	var eapMD5 EapMD5
	challenge := make([]byte, 16)
	err := eapMD5.SetChallengeValue(challenge)
	require.NoError(t, err)
	require.Equal(t, uint8(16), eapMD5.ValueSize)
	require.Equal(t, challenge, eapMD5.Value)

	badChallenge := make([]byte, 15)
	err = eapMD5.SetChallengeValue(badChallenge)
	require.Error(t, err)
}

func TestEapMD5SetName(t *testing.T) {
	var eapMD5 EapMD5
	name := "alice"
	eapMD5.SetName(name)
	require.Equal(t, name, eapMD5.Name)
}
