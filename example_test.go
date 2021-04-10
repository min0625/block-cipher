package blockcipher_test

import (
	"encoding/base64"
	"fmt"

	blockcipher "github.com/min0625/block-cipher"
)

// Example_AesCbc has malformed example suffix: AesCbctests

func Example_aes_cbc() {
	key, err := base64.StdEncoding.DecodeString("eIYnxNiQZ1pmXozI93DJGtjn/VPq+lyiUKlwMGlJlyU=")
	if err != nil {
		panic(err)
	}

	plaintext := []byte(`my plaintext`)
	ciphertext, err := blockcipher.AesCbcEncrypt(key, plaintext)
	if err != nil {
		panic(err)
	}

	plaintext, err = blockcipher.AesCbcDecrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", plaintext)
	// Output: my plaintext
}
