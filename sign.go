package openssl

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

// Sign 加密签名
func (o *Openssl) Sign(data string) (string, error) {
	shaNew := o.hash.New()
	shaNew.Write([]byte(data))

	bytes, err := rsa.SignPKCS1v15(rand.Reader, o.privateKey, o.hash, shaNew.Sum(nil))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}
