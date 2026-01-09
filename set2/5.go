package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"math/rand"
	"net/mail"
	"slices"
	"strconv"
	"strings"
)

type Role int

const (
	User Role = iota
	Admin
)

func (r Role) String() string {
	switch r {
	case User:
		return "user"
	case Admin:
		return "admin"
	default:
		return "none"
	}
}

func (r *Role) Decode(str string) error {
	switch str {
	case "user":
		*r = User
		return nil
	case "admin":
		*r = Admin
		return nil
	}
	return fmt.Errorf("not a valid role: %v %s", []byte(str), str)
}

type Profile struct {
	Email string
	UID   int
	Role  Role
}

func (p Profile) Encode() (string, error) {
	if _, err := mail.ParseAddress(p.Email); err != nil {
		return "", err
	} else if strings.ContainsAny(p.Email, "&=") {
		return "", errors.New("email contains encoding characters")
	}

	return "email=" + p.Email + "&uid=" + strconv.Itoa(p.UID) + "&role=" + p.Role.String(), nil
}

func (p *Profile) Decode(str string) error {
	parts := strings.Split(str, "&")
	for _, part := range parts {
		kvsplit := strings.Split(part, "=")
		if len(kvsplit) != 2 {
			return errors.New("too many equals")
		}

		key := kvsplit[0]
		value := kvsplit[1]

		switch key {
		case "email":
			if _, err := mail.ParseAddress(value); err != nil {
				return err
			}
			p.Email = value
		case "uid":
			var err error
			p.UID, err = strconv.Atoi(value)
			if err != nil {
				return err
			}
		case "role":
			if err := p.Role.Decode(value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid key: %s", key)
		}
	}

	return nil
}

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

func encryptionOracle() func(src []byte, enc bool) []byte {
	key := make([]byte, 16)
	rand.Read(key)

	return func(src []byte, enc bool) []byte {
		iv := make([]byte, 16)

		rand.Read(iv)

		ptxt := PKCS7Pad(src, len(key))
		ctxt := make([]byte, len(ptxt))

		block, err := NewAESECB(key)
		if err != nil {
			panic(err)
		}
		block.handleBytes(ctxt, ptxt, enc)

		return ctxt
	}
}

func main() {
	oracle := encryptionOracle()
	p := Profile{"foo@bar.com", 10, User}
	encoded, _ := p.Encode()
	enc := oracle([]byte(encoded), true)

	startLen := len(slices.Collect(slices.Chunk(enc, 16)))

	for len(slices.Collect(slices.Chunk([]byte(encoded), 16))) == startLen {
		p.Email = p.Email + "m"
		encoded, _ = p.Encode()
		enc = oracle([]byte(encoded), true)
	}

	// admin&uid=100000 has length 16
	p.Email = p.Email + "admin"
	p.UID = 100000

	encoded, _ = p.Encode()
	for v := range slices.Chunk([]byte(encoded), 16) {
		fmt.Println(string(v))
	}
	enc = oracle([]byte(encoded), true)
	chunks := slices.Collect(slices.Chunk(enc, 16))
	adminBlock := make([]byte, 16)
	copy(adminBlock, chunks[2])

	p.Email = p.Email + "adminadasdm"
	p.UID = 10000
	encoded, _ = p.Encode()
	for v := range slices.Chunk([]byte(encoded), 16) {
		fmt.Println(string(v))
	}
	enc = oracle([]byte(encoded), true)
	chunks = slices.Collect(slices.Chunk(enc, 16))
	uidBlock := make([]byte, 16)
	copy(uidBlock, chunks[3])

	p.Email = "f@bar.com"
	p.UID = 10
	encoded, _ = p.Encode()
	for v := range slices.Chunk([]byte(encoded), 16) {
		fmt.Println(string(v))
	}
	enc = oracle([]byte(encoded), true)

	fmt.Println(enc)
	enc = append(enc, uidBlock...)
	enc = append(enc, adminBlock...)
	enc = PKCS7Pad(enc, 16)
	fmt.Println(enc)
	dec := oracle(enc, false)
	//dec = bytes.TrimRight(enc, "\x04")
	fmt.Println(string(dec))
	var decoded Profile
	fmt.Println(decoded.Decode(string(dec)))
	fmt.Println(decoded)
}
