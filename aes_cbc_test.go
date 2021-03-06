package blockcipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const (
	testHexKey = "7aafe7498bd22877079223bd8d7c9b6b3571c156bc00d2c490e812f080808245"
)

func TestAesCbc(t *testing.T) {
	key := mustDecodeString(testHexKey)
	plaintext := []byte("plaintext")
	ciphertext, err := AesCbcEncrypt(key, plaintext)
	if err != nil {
		t.Errorf("AesCbcEncrypt: %v", err)
		return
	}

	decrypted, err := AesCbcDecrypt(key, ciphertext)
	if err != nil {
		t.Errorf("AesCbcDecrypt: %v", err)
		return
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted %v, want %v", decrypted, plaintext)
		return
	}
}

func mustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
