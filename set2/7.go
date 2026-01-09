package main

import (
	"errors"
	"fmt"
	"slices"
)

func PKCS7Pad(x []byte, blen int) []byte {
	missing := (-int(len(x))) % int(blen)
	if missing < 0 {
		missing += int(blen)
	} else if missing == 0 {
		missing = 16
	}

	pad := make([]byte, missing)
	for i := range len(pad) {
		pad[i] = byte(missing)
	}

	return slices.Concat(x, pad)
}

func PKCS7Strip(x []byte, blen int) ([]byte, error) {
	if len(x)%blen != 0 {
		return nil, errors.New("not a multiple of the block length")
	}

	if len(x) == 0 {
		return nil, errors.New("pkcs7 padded string cannot have length zero")
	}

	lastByte := int(x[len(x)-1])
	if lastByte < 1 || lastByte > blen {
		return nil, errors.New("pkcs7 last byte must satisfy 1 <= last byte <= blen")
	}

	for i := len(x) - lastByte; i < len(x); i++ {
		if int(x[i]) != lastByte {
			return nil, errors.New("mismatched padding bytes")
		}
	}

	return x[:len(x)-lastByte], nil
}

func main() {
	padded := PKCS7Pad([]byte("vim-go vim-go vi"), 16)
	fmt.Println(padded)
	fmt.Println(PKCS7Strip(padded, 16))
	padded[len(padded)-1] = 1
	fmt.Println(PKCS7Strip(padded, 16))
}
