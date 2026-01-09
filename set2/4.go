package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
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

func XORBytes(dst, src []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = dst[i] ^ src[i]
	}
}

type CBC struct {
	prevBlock []byte
	block     cipher.Block
	blen      int
}

func NewAESCBC(key, iv []byte) (CBC, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return CBC{}, err
	}

	blen := aes.BlockSize()
	if len(iv) != blen {
		return CBC{}, fmt.Errorf("iv length %d does not match block length %d", len(iv), blen)
	}

	prevBlock := make([]byte, blen)
	copy(prevBlock, iv)
	return CBC{
		prevBlock: prevBlock,
		block:     aes,
		blen:      blen,
	}, nil
}

func (cbc *CBC) handleBlock(dst []byte, block []byte, enc bool) {
	src := make([]byte, cbc.blen)
	copy(src, block)

	res := make([]byte, cbc.blen)
	if enc {
		XORBytes(src, cbc.prevBlock)
		cbc.block.Encrypt(res, src)
		cbc.prevBlock = res
	} else {
		cbc.block.Decrypt(res, src)
		XORBytes(res, cbc.prevBlock)
		copy(cbc.prevBlock, src)
	}

	copy(dst, res)
}

func (cbc *CBC) handleBytes(dst []byte, src []byte, enc bool) {
	blocks := slices.Chunk(src, cbc.blen)

	var blockIdx int
	for block := range blocks {
		cbc.handleBlock(dst[blockIdx*cbc.blen:(blockIdx+1)*cbc.blen], block, enc)
		blockIdx++
	}
}

type ECB struct {
	block cipher.Block
	blen  int
}

func NewAESECB(key []byte) (ECB, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return ECB{}, err
	}

	return ECB{
		block: aes,
		blen:  aes.BlockSize(),
	}, nil
}

func (ecb *ECB) handleBlock(dst []byte, block []byte, enc bool) {
	if enc {
		ecb.block.Encrypt(dst, block)
	} else {
		ecb.block.Decrypt(dst, block)
	}
}

func (ecb *ECB) handleBytes(dst []byte, src []byte, enc bool) {
	blocks := slices.Chunk(src, ecb.blen)

	var blockIdx int
	for block := range blocks {
		ecb.handleBlock(dst[blockIdx*ecb.blen:(blockIdx+1)*ecb.blen], block, enc)
		blockIdx++
	}
}

func encryptionOracle() func(src []byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)

	return func(src []byte) []byte {
		iv := make([]byte, 16)
		suffix, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

		rand.Read(iv)

		ptxt := PKCS7Pad(slices.Concat(src, suffix), len(key))
		ctxt := make([]byte, len(ptxt))

		block, err := NewAESECB(key)
		if err != nil {
			panic(err)
		}
		block.handleBytes(ctxt, ptxt, true)

		return ctxt
	}
}

func main() {
	oracle := encryptionOracle()
	//fmt.Println(hex.EncodeToString(oracle([]byte("AAAAAA"))))
	// 6 bytes to get to new block
	//fmt.Println(len("AAAAAAAAAAAAAAAAAAAAAAA"))
	//fmt.Println(hex.EncodeToString(oracle([]byte("AAAAAAAAAAAAAAAAAAAAAAA"))))
	// 6+17 to get to new block, so block size is 16

	prefix := "AAAAAAAAAAAAAAA"
	decrypted := ""
	blockIdx := 0
	for {
		enc := slices.Collect(slices.Chunk(oracle([]byte(prefix)), 16))
		firstBlock := enc[blockIdx]

		dict := make(map[string]int)
		for i := 0; i < 128; i++ {
			ch := i
			str := fmt.Sprintf("%s%s%c", prefix, decrypted, ch)
			enc := slices.Collect(slices.Chunk(oracle([]byte(str)), 16))
			firstBlock := enc[blockIdx]
			dict[hex.EncodeToString(firstBlock)] = ch
		}

		res, ok := dict[hex.EncodeToString(firstBlock)]
		if !ok {
			panic("no match")
			break
		}
		s := fmt.Sprintf("%c", res)
		fmt.Printf(s)
		decrypted += s
		prefix = prefix[1:]
		if prefix == "" {
			prefix = "AAAAAAAAAAAAAAAA"
			blockIdx++
		}
	}

}
