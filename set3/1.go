package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	mrand "math/rand"
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

func encryptionOracle() (enc func(src []byte) []byte, dec func(src []byte) bool) {
	key := []byte{45, 135, 181, 151, 22, 24, 120, 192, 131, 254, 4, 183, 111, 38, 52, 59}

	return func(src []byte) []byte {
			var dst []byte
			iv := make([]byte, 16)
			rand.Read(iv)

			block, err := NewAESCBC(key, iv)
			if err != nil {
				panic(err)
			}

			ptxt := PKCS7Pad(src, len(key))
			dst = make([]byte, len(ptxt)+16)

			copy(dst, iv)

			block.handleBytes(dst[16:], ptxt, true)

			return dst
		}, func(src []byte) bool {
			dst := make([]byte, len(src)-16)

			iv := src[:16]
			block, err := NewAESCBC(key, iv)
			if err != nil {
				panic(err)
			}

			block.handleBytes(dst, src[16:], false)

			// fmt.Println("dst", dst)

			_, err = PKCS7Strip(dst, 16)
			// fmt.Println(err)
			return err == nil
		}
}

var ptxts = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func main() {
	ptxtIdx := mrand.Intn(len(ptxts))
	ptxt, _ := base64.StdEncoding.DecodeString(ptxts[ptxtIdx])
	fmt.Println(string(ptxt))

	enc, dec := encryptionOracle()

	ctxt := enc(ptxt)
	ctxtChunks := slices.Collect(slices.Chunk(ctxt, 16))
	// fmt.Println("ctxt", ctxt)

	old := make([]byte, len(ctxt))
	copy(old, ctxt)

	ctxtChunks[len(ctxtChunks)-2] = make([]byte, 16)
	unciphered := make([]byte, 16)

	for pos := len(ctxt) - 1; pos >= len(ctxt)-15; pos-- {
		posChunk := pos / 16
		posChunkIdx := pos % 16
		prevChunk := posChunk - 1

		fmt.Println(posChunk, posChunkIdx, prevChunk)

	InnerLoop:
		for i := byte(0); i < 255; i++ {
			ctxtChunks[prevChunk][posChunkIdx] = i
			// fmt.Println(slices.Concat(ctxtChunks...))

			if dec(slices.Concat(ctxtChunks...)) {
				// decryption of last byte is 0x1
				// SECOND_TO_LAST_BLOCK_LAST_BYTE xor DECRYPTION OF LAST BLOCK LAST BYTE = 0x1
				u := ctxtChunks[prevChunk][posChunkIdx] ^ byte(16-posChunkIdx)
				unciphered[posChunkIdx] = u

				actual := u ^ old[prevChunk*16+posChunkIdx]

				fmt.Println("actual", string(actual))

				for j := posChunkIdx; j <= 15; j++ {
					ctxtChunks[prevChunk][j] = unciphered[j] ^ byte(16-posChunkIdx+1)
				}

				dec(slices.Concat(ctxtChunks...))

				break InnerLoop
			}
		}
	}
}
