# FNV-XOR-Mask-Shuffle Symmetric Encryption Algorithm

This is a Go package that implements the FNV-XOR-Mask-Shuffle symmetric encryption algorithm. This algorithm is a combination of several cryptographic techniques that make it difficult for an attacker to decrypt the data.

## Installation

To use this package, you can install it using go get command:

```bash
go get github.com/NIR3X/fxms
```

## Usage

Here is an example of how to use this package:

```go
package main

import (
	"fmt"
	"github.com/NIR3X/fxms"
)

func main() {
	// Generate a random key
	key := fxms.GenKey()

	// Data to encrypt
	data := []uint8("Hello, World!")

	// Encrypt the data
	encrypted, err := fxms.Encrypt(key, data, fxms.OptimizeDecryption)
	if err != nil {
		panic(err)
	}

	// Decrypt the data
	decrypted, ok, err := fxms.Decrypt(key, encrypted, fxms.OptimizeDecryption)
	if err != nil {
		panic(err)
	}

	if !ok {
		panic("Decryption failed")
	}

	// Print the decrypted data
	fmt.Printf("%s\n", decrypted)
}
```
