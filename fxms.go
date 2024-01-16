package fxms

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strconv"
)

// Mode represents the different modes of operation.
type Mode uint8

const (
	// HashLen represents the length of the hash.
	HashLen = 8
	// MaskLen represents the length of the mask.
	MaskLen = 16
	// KeyLen represents the length of the key.
	KeyLen = 256

	// OptimizeEncryption is used to optimize encryption.
	OptimizeEncryption Mode = 0
	// OptimizeDecryption is used to optimize decryption.
	OptimizeDecryption Mode = 1
)

// getHash calculates the hash value of the given data using the FNV-1a 64-bit algorithm.
// It takes a byte slice as input and returns a 64-bit unsigned integer as the hash value.
func getHash(data []uint8) uint64 {
	return fnv1a64Hash(data)
}

// GenKey generates a random key of type []uint8.
// It uses the crypto/rand package to generate a secure random key.
// The length of the key is determined by the constant KeyLen.
// Returns the generated key.
func GenKey() []uint8 {
	key := make([]uint8, KeyLen)
	rand.Read(key)
	return key
}

// Encrypt encrypts the source data using the provided key and mode.
// It returns the encrypted data and an error if any.
// The key must be a byte slice with a length between 1 and 256.
// The source data must be a byte slice.
// The mode parameter determines the encryption mode.
// If mode is OptimizeEncryption, the key and result will be shuffled.
// If mode is not OptimizeEncryption, the key and result will be unshuffled.
func Encrypt(key, src []uint8, mode Mode) ([]uint8, error) {
	keyLen := len(key)
	if keyLen < 1 || keyLen > 256 {
		return nil, errors.New("fxms: invalid key size " + strconv.Itoa(keyLen))
	}
	srcLen := len(src)
	resultLen := HashLen + MaskLen + srcLen
	result := make([]uint8, resultLen)
	binary.LittleEndian.PutUint64(result, getHash(src))
	mask := result[HashLen:][:MaskLen]
	rand.Read(mask)
	dest := result[HashLen+MaskLen:]
	for i := 0; i < srcLen; i++ {
		dest[i] = src[i] ^ mask[i%MaskLen] ^ key[i%keyLen]
	}
	if mode == OptimizeEncryption {
		_ = shufflerShuffle(key, result) // we don't care about the error, we already know the key is valid
	} else {
		_ = shufflerUnshuffle(key, result) // we don't care about the error, we already know the key is valid
	}
	return result, nil
}

// Decrypt decrypts the given source data using the provided key and mode.
// It returns the decrypted data, a boolean indicating whether the decryption was successful,
// and an error if any occurred.
// The key must be a byte slice with a length between 1 and 256.
// The source data must have a length greater than or equal to MaskLen + HashLen.
// If the mode is OptimizeEncryption, the source data is unshuffled using the key.
// If the mode is not OptimizeEncryption, the source data is shuffled using the key.
func Decrypt(key, src []uint8, mode Mode) ([]uint8, bool, error) {
	keyLen := len(key)
	if keyLen < 1 || keyLen > 256 {
		return nil, false, errors.New("fxms: invalid key size " + strconv.Itoa(keyLen))
	}
	srcLen := len(src)
	dataLen := srcLen - MaskLen - HashLen
	if dataLen < 0 {
		return nil, false, errors.New("fxms: invalid data size")
	}
	if mode == OptimizeEncryption {
		_ = shufflerUnshuffle(key, src) // we don't care about the error, we already know the key is valid
	} else {
		_ = shufflerShuffle(key, src) // we don't care about the error, we already know the key is valid
	}
	mask := src[HashLen:][:MaskLen]
	data := src[HashLen+MaskLen:]
	dest := make([]uint8, dataLen)
	for i := 0; i < dataLen; i++ {
		dest[i] = data[i] ^ mask[i%MaskLen] ^ key[i%keyLen]
	}
	return dest, getHash(dest) == binary.LittleEndian.Uint64(src), nil
}
