package openssl

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func ParsePrivateKeyText(privateKeyText []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyText)
	if block == nil {
		return nil, errors.New("私钥信息错误！")
	}

	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priKey, nil
}

func ParsePublicKeyText(publicKeyText []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyText)
	if block == nil {
		return nil, errors.New("公钥信息错误！")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey.(*rsa.PublicKey), nil
}
