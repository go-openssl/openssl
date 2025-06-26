package openssl

import (
	"crypto/rand"
	"crypto/rsa"
)

// Encrypt 公钥加密
func (o *Openssl) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, o.publicKey, data)
}
