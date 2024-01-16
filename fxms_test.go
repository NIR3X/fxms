package fxms

import (
	"testing"
)

// TestEncryptionAndDecryption tests the encryption and decryption functionality.
// It generates a random key, encrypts a data, and then decrypts it using the same key.
// Finally, it checks if the decrypted data matches the original data.
func TestEncryptionAndDecryption(t *testing.T) {
	// Generate a random key
	key := GenKey()

	// Data to encrypt
	data := []uint8("Hello, World!")

	// Encrypt the data
	encrypted, err := Encrypt(key, data, OptimizeDecryption)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt the data
	decrypted, ok, err := Decrypt(key, encrypted, OptimizeDecryption)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !ok {
		t.Fatal("Decryption failed")
	}

	// Check if the decrypted data matches the original data
	if string(decrypted) != string(data) {
		t.Fatalf("Mismatch: expected %s, got %s", string(data), string(decrypted))
	}
}
