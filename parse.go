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
		if err.Error() == "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)" {
			var _priKey any
			if _priKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, err
			}
			priKey = _priKey.(*rsa.PrivateKey)
		} else {
			return nil, err
		}
	}

	return priKey, nil
}

func ParsePublicKeyText(publicKeyText []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyText)
	if block == nil {
		return nil, errors.New("公钥信息错误！")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		if err.Error() == "x509: failed to parse public key (use ParsePKIXPublicKey instead for this key format)" {
			var _pubKey any
			if _pubKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				return nil, err
			}
			pubKey = _pubKey.(*rsa.PublicKey)
		} else {
			return nil, err
		}
	}

	return pubKey, nil
}
