package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

const (
	EndOfTransmission byte = 0x04
)

func PKCS7Pad(x []byte, blen int) []byte {
	missing := (-len(x)) % blen
	if missing < 0 {
		missing += blen
	}

	pad := make([]byte, missing)
	for i := 0; i < len(pad); i++ {
		pad[i] = EndOfTransmission
	}

	return slices.Concat(x, pad)
}

func PKCS7Strip(x []byte) ([]byte, error) {
	idx := bytes.Index(x, []byte{EndOfTransmission})
	if idx == -1 {
		return nil, errors.New("no end of transmission byte (0x04) was found")
	}

	return x[:idx], nil

}

func main() {
	padded := PKCS7Pad([]byte("vim-go"), 16)
	fmt.Println(padded)
	fmt.Println(PKCS7Strip(padded))
}
