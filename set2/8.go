package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"math/rand"
	"slices"
)

func PKCS7Pad(x []byte, blen int) []byte {
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

func encryptionOracle() func(src []byte, enc bool) []byte {
	key := []byte{45, 135, 181, 151, 22, 24, 120, 192, 131, 254, 4, 183, 111, 38, 52, 59}

	return func(src []byte, enc bool) []byte {
		var dst []byte
		if enc {
			iv := make([]byte, 16)
			rand.Read(iv)

			block, err := NewAESCBC(key, iv)
			if err != nil {
				panic(err)
			}

			prefix := []byte("comment1=cooking%20MCs;userdata=")
			suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

			ptxt := PKCS7Pad(slices.Concat(prefix, src, suffix), len(key))
			dst = make([]byte, len(ptxt)+16)

			copy(dst, iv)

			block.handleBytes(dst[16:], ptxt, enc)
		} else {
			dst = make([]byte, len(src)-16)

			iv := src[:16]
			block, err := NewAESCBC(key, iv)
			if err != nil {
				panic(err)
			}

			block.handleBytes(dst, src[16:], enc)
		}

		return dst
	}
}

func main() {
	oracle := encryptionOracle()
	ctxt := oracle([]byte("foobar"), true)
	ptxt := oracle(ctxt, false)
	fmt.Println(string(ptxt), ptxt[0])
	zeroBlock := make([]byte, 16)
	copy(ctxt, zeroBlock)
	ptxt = oracle(ctxt, false)
	fmt.Println(string(ptxt), ptxt[0])
	rawDecrypted := ptxt[:16]
	inj := []byte("admin=true;;;;;;")
	XORBytes(rawDecrypted, inj)
	copy(ctxt, rawDecrypted)
	ptxt = oracle(ctxt, false)
	fmt.Println(string(ptxt), ptxt[0])

	/*inj := []byte("admin=true;")
	for i := range inj {
		pos := 16 + i
		// when ctxt[pos] was what it was, we XORed with decrypted block 3 to get
		// ptxt[pos], so ctxt[pos] + foo = ptxt[pos]
		// so foo = ptxt[pos] - ctx[pos]
		// ctxt[pos]' + foo = 'a'
		// ctx[pos]' = 'a' - (ptxt[pos] - ctx[pos])
		ctxt[pos] = byte(int(inj[i]) - (int(ptxt[pos]) - int(ctxt[pos])))
	}
	ptxt = oracle(ctxt, false)
	fmt.Println(string(ptxt))
	*/
}
