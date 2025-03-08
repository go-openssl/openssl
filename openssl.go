package openssl

import (
	"crypto"
	"crypto/rsa"
)

type Openssl struct {
	hash       crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func New(opts ...Option) (*Openssl, error) {
	openssl := &Openssl{
		hash: crypto.SHA256,
	}

	for _, opt := range opts {
		if err := opt(openssl); err != nil {
			return nil, err
		}
	}

	return openssl, nil
}
