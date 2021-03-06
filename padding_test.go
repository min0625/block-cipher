package blockcipher

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPkcs7Padding(t *testing.T) {
	tests := []struct {
		data      []byte
		blockSize int
		padded    []byte
	}{
		{
			data:      []byte{1, 2, 3, 4, 5, 6, 7},
			blockSize: 8,
			padded:    []byte{1, 2, 3, 4, 5, 6, 7, 1},
		},
		{
			data:      []byte{1, 2, 3, 4, 5, 6, 7, 8},
			blockSize: 8,
			padded:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			data:      []byte{1, 2, 3, 4, 5, 6, 7},
			blockSize: 3,
			padded:    []byte{1, 2, 3, 4, 5, 6, 7, 2, 2},
		},
		{
			data:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			blockSize: 3,
			padded:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 3, 3, 3},
		},
	}
	for idx, tt := range tests {
		t.Run(fmt.Sprintf("test-%d", idx+1), func(t *testing.T) {
			padded, err := Pkcs7Padding(tt.data, tt.blockSize)
			if err != nil {
				t.Errorf("Pkcs7Padding() error: %v", err)
				return
			}

			if !bytes.Equal(padded, tt.padded) {
				t.Errorf("Pkcs7Padding() = %v, want %v", padded, tt.padded)
				return
			}

			rawData, err := Pkcs7UnPadding(padded)
			if err != nil {
				t.Errorf("Pkcs7UnPadding() error: %v", err)
				return
			}

			if !bytes.Equal(rawData, tt.data) {
				t.Errorf("Pkcs7UnPadding() = %v, want %v", rawData, tt.data)
				return
			}
		})
	}
}
