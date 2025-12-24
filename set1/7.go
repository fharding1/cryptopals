package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

var key = []byte("YELLOW SUBMARINE")

func main() {
	f, _ := os.Open("7.txt")
	defer f.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, f)
	cipher, _ := aes.NewCipher(key)

	enc := make([]byte, cipher.BlockSize())
	dec := make([]byte, cipher.BlockSize())
	_, err := io.ReadFull(decoder, enc)
	for err == nil {
		cipher.Decrypt(dec, enc)
		_, err = io.ReadFull(decoder, enc)
		fmt.Println(string(dec))
	}
}
