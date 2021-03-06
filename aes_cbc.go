package blockcipher

import "crypto/aes"

func AesCbcDecrypt(key []byte, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return CbcDecrypt(block, ciphertext)
}

func AesCbcEncrypt(key []byte, plaintext []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return CbcEncrypt(block, plaintext)
}
