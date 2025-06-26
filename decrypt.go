package openssl

import (
	"crypto/rand"
	"crypto/rsa"
)

func (o *Openssl) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, o.privateKey, data)
}
