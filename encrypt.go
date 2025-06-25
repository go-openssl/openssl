package openssl

import (
	"crypto/rand"
	"crypto/rsa"
)

// Encrypt 公钥加密
func (o *Openssl) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(o.hash.New(), rand.Reader, o.publicKey, data, nil)
}
