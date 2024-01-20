# FNV-XOR-Mask-Shuffle Symmetric Encryption Algorithm

This is a Go package that implements the FNV-XOR-Mask-Shuffle symmetric encryption algorithm. This algorithm is a combination of several cryptographic techniques that make it difficult for an attacker to decrypt the data.

## Installation

To use this package, you can install it using go get command:

```bash
go get -u github.com/NIR3X/fxms
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

## License
[![GNU AGPLv3 Image](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)  

This program is Free Software: You can use, study share and improve it at your
will. Specifically you can redistribute and/or modify it under the terms of the
[GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.html) as
published by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
