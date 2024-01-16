package fxms

// offsetBasis is the initial value used in the FNV-1a 64-bit hash algorithm.
// prime is the prime number used in the FNV-1a 64-bit hash algorithm.
const offsetBasis, prime uint64 = 0xcbf29ce484222325, 0x00000100000001b3

// fnv1a64Hash calculates the FNV-1a 64-bit hash of the given source byte slice.
// It iterates over each byte in the slice, XORs it with the current hash value,
// and multiplies the result by a prime number. The final hash value is returned.
func fnv1a64Hash(src []uint8) uint64 {
	hash := offsetBasis
	for _, b := range src {
		hash ^= uint64(b)
		hash *= prime
	}
	return hash
}
