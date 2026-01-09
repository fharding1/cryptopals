package main

import (
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

func main() {
	fmt.Printf("%d\n", PKCS7Pad([]byte("YELLOW SUBMARINE"), 20))
	fmt.Printf("%d\n", PKCS7Pad([]byte("YELLOW SUBMA"), 20))
}
