package dh

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// BenchmarkDH_2048_GetPublicValue benchmarks the public value computation.
// This is the g^secret mod p operation.
func BenchmarkDH_2048_GetPublicValue(b *testing.B) {
	// Initialize DH group
	dhType := StrToType(DH_2048_BIT_MODP)
	if dhType == nil {
		b.Fatalf("Failed to get DH_2048_BIT_MODP")
	}

	// Generate a random secret
	maxVal := new(big.Int)
	maxVal.SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74", 16)
	secret, err := rand.Int(rand.Reader, maxVal)
	if err != nil {
		b.Fatalf("Failed to generate random secret: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dhType.GetPublicValue(secret)
	}
}

// BenchmarkDH_2048_GetSharedKey benchmarks the shared key computation.
// This is the peerPublicValue^secret mod p operation.
func BenchmarkDH_2048_GetSharedKey(b *testing.B) {
	// Initialize DH group
	dhType := StrToType(DH_2048_BIT_MODP)
	if dhType == nil {
		b.Fatalf("Failed to get DH_2048_BIT_MODP")
	}

	// Generate random values
	maxVal := new(big.Int)
	maxVal.SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74", 16)
	secret, err := rand.Int(rand.Reader, maxVal)
	if err != nil {
		b.Fatalf("Failed to generate random secret: %v", err)
	}

	// Generate peer public value
	peerPublicValue := new(big.Int).SetBytes(dhType.GetPublicValue(secret))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dhType.GetSharedKey(secret, peerPublicValue)
	}
}

// BenchmarkDH_2048_Combined benchmarks both operations together (full DH exchange).
func BenchmarkDH_2048_Combined(b *testing.B) {
	// Initialize DH group
	dhType := StrToType(DH_2048_BIT_MODP)
	if dhType == nil {
		b.Fatalf("Failed to get DH_2048_BIT_MODP")
	}

	maxVal := new(big.Int)
	maxVal.SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74", 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate random secret
		secret, err := rand.Int(rand.Reader, maxVal)
		if err != nil {
			b.Fatalf("Failed to generate random secret: %v", err)
		}

		// Get public value
		localPubValue := dhType.GetPublicValue(secret)

		// Simulate peer's public value (use our public value as peer's)
		peerPublicValue := new(big.Int).SetBytes(localPubValue)

		// Get shared key
		_ = dhType.GetSharedKey(secret, peerPublicValue)
	}
}

// BenchmarkDH_Concurrent tests concurrent DH operations.
// This benchmark simulates what happens with multiple workers.
func BenchmarkDH_2048_Concurrent(b *testing.B) {
	dhType := StrToType(DH_2048_BIT_MODP)
	if dhType == nil {
		b.Fatalf("Failed to get DH_2048_BIT_MODP")
	}

	maxVal := new(big.Int)
	maxVal.SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74", 16)

	// Run benchmark with multiple goroutines
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Generate random secret
			secret, err := rand.Int(rand.Reader, maxVal)
			if err != nil {
				b.Fatalf("Failed to generate random secret: %v", err)
			}

			// Get public value
			localPubValue := dhType.GetPublicValue(secret)

			// Simulate peer's public value
			peerPublicValue := new(big.Int).SetBytes(localPubValue)

			// Get shared key
			_ = dhType.GetSharedKey(secret, peerPublicValue)
		}
	})
}

// BenchmarkDH_1024_Combined benchmarks 1024-bit MODP DH (for comparison).
func BenchmarkDH_1024_Combined(b *testing.B) {
	// Initialize DH group
	dhType := StrToType(DH_1024_BIT_MODP)
	if dhType == nil {
		b.Fatalf("Failed to get DH_1024_BIT_MODP")
	}

	maxVal := new(big.Int)
	maxVal.SetString("FFFFFFFFFFFFF8000000000000000000000000000000000000000", 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate random secret (smaller for 1024-bit)
		secret, err := rand.Int(rand.Reader, maxVal)
		if err != nil {
			b.Fatalf("Failed to generate random secret: %v", err)
		}

		// Get public value
		localPubValue := dhType.GetPublicValue(secret)

		// Simulate peer's public value
		peerPublicValue := new(big.Int).SetBytes(localPubValue)

		// Get shared key
		_ = dhType.GetSharedKey(secret, peerPublicValue)
	}
}
