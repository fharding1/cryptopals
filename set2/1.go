package main

import (
	"fmt"
	"slices"
)

const (
	EndOfTransmission byte = 0x04
)

func PKCS7Pad(x []byte, blen uint) []byte {
	missing := (-int(len(x))) % int(blen)
	if missing < 0 {
		missing += int(blen)
	}

	pad := make([]byte, missing)
	for i := 0; i < len(pad); i++ {
		pad[i] = EndOfTransmission
	}

	return slices.Concat(x, pad)
}

func main() {
	fmt.Printf("%d\n", PKCS7Pad([]byte("YELLOW SUBMARINE"), 20))
}
