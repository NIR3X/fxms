package fxms

import (
	"crypto/rc4"
	"encoding/binary"
)

// shufflerShuffle shuffles the data using the RC4 cipher algorithm.
// It takes a key and data as input and returns an error if there is any.
// The function uses the RC4 cipher to generate a random index 'j' and swaps the elements at indices 'i' and 'j' in the data array.
// This process is repeated for each element in the data array, resulting in a shuffled data array.
func shufflerShuffle(key, data []uint8) error {
	rc4cipher, err := rc4.NewCipher(key)
	if err != nil {
		return err
	}
	dataLen := len(data)
	for i := 0; i < dataLen; i++ {
		jRaw := []uint8{0, 0, 0, 0, 0, 0, 0, 0}
		rc4cipher.XORKeyStream(jRaw, jRaw)
		j := binary.LittleEndian.Uint64(jRaw)
		j %= uint64(dataLen)
		if uint64(i) != j {
			temp := data[i]
			data[i] = data[j]
			data[j] = temp
		}
	}
	return nil
}

// shufflerUnshuffle is the vice-versa method to shufflerShuffle.
// It takes a key and data as input, and unshuffles the data using the RC4 cipher algorithm.
// The unshuffled data is modified in-place.
// If an error occurs during the cipher initialization, it is returned.
func shufflerUnshuffle(key, data []uint8) error {
	rc4cipher, err := rc4.NewCipher(key)
	if err != nil {
		return err
	}
	dataLen := len(data)
	jArr := make([]uint64, dataLen)
	for i := 0; i < dataLen; i++ {
		jRaw := []uint8{0, 0, 0, 0, 0, 0, 0, 0}
		rc4cipher.XORKeyStream(jRaw, jRaw)
		j := binary.LittleEndian.Uint64(jRaw)
		j %= uint64(dataLen)
		jArr[i] = j
	}
	for i := dataLen - 1; i != -1; i-- {
		j := jArr[i]
		if uint64(i) != j {
			temp := data[i]
			data[i] = data[j]
			data[j] = temp
		}
	}
	return nil
}
