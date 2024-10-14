package encr

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	sk_ei_196 = []byte{
		0xa0, 0x0a, 0x7b, 0xb9, 0x2b, 0x05, 0xf9, 0x34,
		0x92, 0x15, 0x72, 0xcd, 0xca, 0x00, 0xa0, 0xdf,
		0x06, 0x4b, 0xba, 0xd3, 0x3e, 0x15, 0x15, 0x4e,
	}
	iv_nil_196 = []byte{
		0x2a, 0xe6, 0xef, 0x86, 0xa9, 0x22, 0x92, 0x98,
		0x2f, 0xa5, 0x66, 0x24, 0x10, 0xad, 0x5a, 0x4b,
	}
	padding_nil_196 = []byte{
		0xa4, 0x9b, 0x11, 0x3a, 0x38, 0xca, 0x76, 0x59,
		0xe6, 0x0b, 0x68, 0x3d, 0x80, 0x96, 0x3a, 0x0f,
	}
	cipherText_nil_196 = []byte{
		0x2a, 0xe6, 0xef, 0x86, 0xa9, 0x22, 0x92, 0x98,
		0x2f, 0xa5, 0x66, 0x24, 0x10, 0xad, 0x5a, 0x4b,
		0x72, 0xe6, 0x5a, 0x40, 0x6d, 0xc6, 0xb8, 0xaf,
		0x11, 0xc4, 0xbc, 0xb1, 0x31, 0x35, 0xc5, 0x19,
	}
	iv_196 = []byte{
		0x51, 0x8d, 0xb4, 0x69, 0x19, 0x5a, 0xca, 0x2e,
		0x08, 0x9d, 0xa0, 0xcd, 0x0d, 0xbc, 0x56, 0x72,
	}
	padding_196 = []byte{
		0xd5, 0x4e, 0x5b, 0x27, 0xf4, 0xd6, 0xa3, 0x07,
	}
	plainText_196 = []byte{
		0x29, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x00,
		0x0a, 0x0a, 0x00, 0xca, 0x24, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x40, 0x00, 0x27, 0x00, 0x00, 0x0c,
		0x01, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x5e,
		0x21, 0x00, 0x00, 0x1c, 0x02, 0x00, 0x00, 0x00,
		0xfe, 0x80, 0x67, 0xe4, 0x8a, 0xe2, 0x3e, 0x60,
		0x21, 0x7b, 0x0c, 0x91, 0xee, 0x8f, 0xef, 0x76,
		0xc9, 0x10, 0x9a, 0xce, 0x2c, 0x00, 0x00, 0x2c,
		0x00, 0x00, 0x00, 0x28, 0x01, 0x03, 0x04, 0x03,
		0xcb, 0xf8, 0xd2, 0xd7, 0x03, 0x00, 0x00, 0x0c,
		0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e, 0x00, 0xc0,
		0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x00,
		0x2d, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00,
		0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0xff, 0xff,
		0x0a, 0x0a, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0xff,
		0x29, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00,
		0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0xff, 0xff,
		0x0a, 0x0a, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0xff,
		0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x0c,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0x0a, 0x64, 0x64, 0x7c, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0xac, 0x10, 0x16, 0xfd,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0xac, 0x10, 0x06, 0xfd, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0xac, 0x1f, 0xff, 0xff,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0xac, 0x11, 0x00, 0x01, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0x0a, 0x64, 0x64, 0x0c,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0xac, 0x10, 0x3d, 0x01, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0xac, 0x10, 0x3e, 0x01,
		0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x14,
		0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x21,
		0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x24,
	}
	cipherText_196 = []byte{
		0x51, 0x8d, 0xb4, 0x69, 0x19, 0x5a, 0xca, 0x2e,
		0x08, 0x9d, 0xa0, 0xcd, 0x0d, 0xbc, 0x56, 0x72,
		0xe0, 0x63, 0x6f, 0x4e, 0xa9, 0xf9, 0x90, 0xfa,
		0xc0, 0x0a, 0xbf, 0xb7, 0x9d, 0x61, 0x99, 0x19,
		0xb1, 0xca, 0x77, 0x53, 0xed, 0xbe, 0x74, 0x73,
		0x3d, 0x24, 0x33, 0x67, 0x96, 0xa9, 0x47, 0x75,
		0x8e, 0xcb, 0x21, 0x95, 0xb4, 0x40, 0x6e, 0x98,
		0xb8, 0x6d, 0x68, 0x6f, 0x58, 0x8e, 0x4a, 0x7b,
		0x4d, 0x34, 0x3f, 0x19, 0xf6, 0x5d, 0xb9, 0x71,
		0x4b, 0xcd, 0x5c, 0x14, 0x70, 0xb9, 0x60, 0x17,
		0x25, 0xa1, 0x5a, 0x4f, 0x19, 0xcb, 0xe4, 0xf3,
		0x80, 0x97, 0x55, 0xa4, 0xcb, 0x2e, 0x8f, 0x46,
		0xdd, 0x16, 0xf2, 0x15, 0x4e, 0x4a, 0x9c, 0xe1,
		0x4d, 0x37, 0x33, 0xfc, 0x83, 0xbe, 0x63, 0xfd,
		0xb3, 0xf6, 0xd8, 0x03, 0x30, 0x82, 0x7b, 0xe9,
		0xc7, 0x1c, 0xc7, 0x5f, 0x8a, 0x5c, 0x79, 0xaf,
		0xfa, 0x14, 0x3e, 0xd7, 0xe4, 0xa6, 0x16, 0xf3,
		0xb7, 0xd0, 0xe2, 0xc4, 0x94, 0x13, 0x27, 0x9e,
		0x30, 0xda, 0x71, 0x33, 0x65, 0x47, 0x6f, 0xc4,
		0xe5, 0xd0, 0x8f, 0x1a, 0xf6, 0x8f, 0x26, 0xfb,
		0x57, 0x0f, 0x8c, 0xdd, 0x9b, 0x22, 0xc4, 0x3f,
		0x4d, 0x84, 0x6a, 0xd6, 0x17, 0xe3, 0xbb, 0x89,
		0x45, 0xdf, 0x7e, 0x59, 0xba, 0xcf, 0xb2, 0x42,
		0x2d, 0x01, 0x9d, 0x64, 0xbc, 0xe8, 0x7b, 0x8a,
		0xa9, 0xd8, 0xc6, 0x9d, 0x93, 0xc2, 0x9f, 0x94,
		0x0f, 0x3c, 0xea, 0x3f, 0xd5, 0x35, 0x01, 0x65,
		0x3b, 0x17, 0x7e, 0xbe, 0x51, 0x18, 0xa3, 0x09,
		0x4b, 0x43, 0xb6, 0xea, 0x11, 0xd3, 0xd8, 0xc1,
		0x7a, 0x8e, 0x1b, 0x31, 0x45, 0xbe, 0xfa, 0x1e,
		0x24, 0xf1, 0x13, 0x4b, 0x5a, 0x90, 0x2e, 0x2c,
		0x9b, 0x64, 0xb6, 0xcd, 0x32, 0xa7, 0x5c, 0xce,
		0xa5, 0x9a, 0xab, 0xf8, 0xc9, 0x4c, 0xbe, 0xc7,
		0xd6, 0xe3, 0x94, 0x50, 0x27, 0x65, 0x0f, 0x84,
		0x28, 0x64, 0xf8, 0x9f, 0x18, 0x87, 0x4d, 0xfe,
		0xe6, 0xee, 0x2f, 0x65, 0x6c, 0xbd, 0xcb, 0xd7,
		0x8a, 0x13, 0x47, 0x9f, 0x15, 0x39, 0x22, 0x70,
		0x28, 0x8c, 0x28, 0xc0, 0x99, 0x2e, 0x24, 0x17,
		0x33, 0xf8, 0xdf, 0xc8, 0x09, 0x78, 0x22, 0x50,
	}
)

func TestEncrypt_196(t *testing.T) {
	var sk EncrAesCbcCrypto
	var block cipher.Block
	var err error
	var cipher []byte

	block, err = aes.NewCipher(sk_ei_196)
	require.NoError(t, err)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_nil_196,
		Padding: padding_nil_196,
	}
	cipher, err = sk.Encrypt(nil)
	require.NoError(t, err)
	require.Equal(t, cipherText_nil_196, cipher)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_196,
		Padding: padding_196,
	}
	cipher, err = sk.Encrypt(plainText_196)
	require.NoError(t, err)
	require.Equal(t, cipherText_196, cipher)
}

func TestDecrypt_196(t *testing.T) {
	var sk EncrAesCbcCrypto
	var err error
	var block cipher.Block
	var plain []byte

	block, err = aes.NewCipher(sk_ei_196)
	require.NoError(t, err)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_nil_196,
		Padding: padding_nil_196,
	}
	plain, err = sk.Decrypt(cipherText_nil_196)
	require.NoError(t, err)
	testnil := make([]byte, 0)
	require.Equal(t, testnil, plain)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_196,
		Padding: padding_196,
	}
	plain, err = sk.Decrypt(cipherText_196)
	require.NoError(t, err)
	require.Equal(t, plainText_196, plain)
}
