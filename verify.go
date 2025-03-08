package openssl

import (
	"crypto/rsa"
	"encoding/base64"
)

// Verify 验证签名
func (o *Openssl) Verify(data, ciphertext string) (bool, error) {
	_ciphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return false, err
	}

	shaNew := o.hash.New()
	shaNew.Write([]byte(data))
	if err = rsa.VerifyPKCS1v15(o.publicKey, o.hash, shaNew.Sum(nil), _ciphertext); err != nil {
		return false, err
	}

	return true, nil
}
