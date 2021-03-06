package blockcipher

import (
	"crypto/cipher"
	"errors"

	"github.com/min0625/gotoken"
)

func CbcDecrypt(block cipher.Block, ciphertext []byte) (plaintext []byte, err error) {
	blockSize := block.BlockSize()
	if len(ciphertext) < blockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext = make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return Pkcs7UnPadding(plaintext)
}

func CbcEncrypt(block cipher.Block, plaintext []byte) (ciphertext []byte, err error) {
	iv, err := gotoken.GenerateBytes(block.BlockSize())
	if err != nil {
		return nil, err
	}
	return cbcEncryptWithIV(block, iv, plaintext)
}

func cbcEncryptWithIV(block cipher.Block, iv []byte, plaintext []byte) (ciphertext []byte, err error) {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("iv length must equal block size")
	}

	plaintext, err = Pkcs7Padding(plaintext, blockSize)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext = make([]byte, blockSize+len(plaintext))
	copy(ciphertext[:blockSize], iv[:])
	mode := cipher.NewCBCEncrypter(block, iv[:])
	mode.CryptBlocks(ciphertext[blockSize:], plaintext)
	return ciphertext, nil
}
