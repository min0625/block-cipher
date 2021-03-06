package blockcipher

import (
	"bytes"
	"errors"
	"fmt"
)

func Pkcs7Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 256 {
		return nil, fmt.Errorf("invalid pkcs7 block size %d", blockSize)
	}
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...), nil
}

func Pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}
	padLen := int(data[length-1])
	if length < padLen {
		return nil, errors.New("invalid pkcs7 padding")
	}
	return data[:(length - padLen)], nil
}
