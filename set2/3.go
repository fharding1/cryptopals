package main

import (
	"crypto/aes"
	"crypto/cipher"
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

func encryptionOracle() (func(src []byte) []byte, bool) {
	cbc := rand.Intn(2) == 0
	return func(src []byte) []byte {
		key := make([]byte, 16)
		iv := make([]byte, 16)
		prefix := make([]byte, 5+rand.Intn(5))
		suffix := make([]byte, 5+rand.Intn(5))

		rand.Read(key)
		rand.Read(iv)
		rand.Read(prefix)
		rand.Read(suffix)

		ptxt := PKCS7Pad(slices.Concat(prefix, src, suffix), len(key))
		ctxt := make([]byte, len(ptxt))
		if cbc {
			cbc = true
			block, err := NewAESCBC(key, iv)
			if err != nil {
				panic(err)
			}
			block.handleBytes(ctxt, ptxt, true)
		} else {
			block, err := NewAESECB(key)
			if err != nil {
				panic(err)
			}
			block.handleBytes(ctxt, ptxt, true)
		}

		return ctxt
	}, cbc
}

func decideOracle(oracle func([]byte) []byte) bool {
	ptxt := make([]byte, 16*20)
	ctxt := oracle(ptxt)
	blocks := slices.Collect(slices.Chunk(ctxt, 16))
	return !slices.Equal(blocks[len(blocks)/2], blocks[len(blocks)/2+1])
}

func main() {
	oracle, cbc := encryptionOracle()
	fmt.Println(cbc)
	fmt.Println(decideOracle(oracle))
}
