package openssl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
)

// Encrypt 公钥加密
func (o *Openssl) Encrypt(data []byte, subLen ...int) ([]byte, error) {
	if len(subLen) == 0 || subLen[0] <= 0 {
		return rsa.EncryptPKCS1v15(rand.Reader, o.publicKey, data)
	}
	// 分段加密
	str := string(data)
	length := len(str)
	sl := subLen[0]
	offset := 0
	buffer := bytes.Buffer{}
	for offset < length {
		endIndex := offset + sl
		if endIndex > length {
			endIndex = length
		}
		ciphers, err := rsa.EncryptPKCS1v15(rand.Reader, o.publicKey, []byte(str[offset:endIndex]))
		if err != nil {
			return nil, err
		}
		buffer.Write(ciphers)
		offset = endIndex
	}
	return buffer.Bytes(), nil
}
