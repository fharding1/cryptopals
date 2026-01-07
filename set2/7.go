package main

import (
	"errors"
	"fmt"
	"slices"
)

func PKCS7Pad(x []byte, blen uint) []byte {
	missing := (-int(len(x))) % int(blen)
	if missing < 0 {
		missing += int(blen)
	}

	pad := make([]byte, missing)
	for i := 0; i < len(pad); i++ {
		pad[i] = byte(missing)
	}

	return slices.Concat(x, pad)
}

func PKCS7Strip(x []byte, blen int) ([]byte, error) {
	if len(x)%blen != 0 {
		return nil, errors.New("not a multiple of the block length")
	}

	if len(x) == 0 {
		return nil, nil
	}

	lastByte := int(x[len(x)-1])
	if lastByte >= blen {
		return x, nil
	}

	for i := len(x) - lastByte; i < len(x); i++ {
		if int(x[i]) != lastByte {
			return nil, errors.New("mismatched padding bytes")
		}
	}

	return x[:len(x)-lastByte], nil
}

func main() {
	padded := PKCS7Pad([]byte("vim-go vim-go vim"), 16)
	fmt.Println(padded)
	fmt.Println(PKCS7Strip(padded, 16))
}
