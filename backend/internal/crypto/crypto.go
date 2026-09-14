package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type Box struct{ key []byte }

func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	return &Box{key: key}, nil
}
func (b *Box) Encrypt(s string) (string, error) {
	block, _ := aes.NewCipher(b.key)
	g, _ := cipher.NewGCM(block)
	n := make([]byte, g.NonceSize())
	if _, e := io.ReadFull(rand.Reader, n); e != nil {
		return "", e
	}
	out := g.Seal(n, n, []byte(s), nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}
func (b *Box) Decrypt(s string) (string, error) {
	raw, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		return "", e
	}
	block, _ := aes.NewCipher(b.key)
	g, _ := cipher.NewGCM(block)
	if len(raw) < g.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	n, c := raw[:g.NonceSize()], raw[g.NonceSize():]
	p, e := g.Open(nil, n, c, nil)
	return string(p), e
}
