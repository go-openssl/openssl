package openssl

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"os"

	"github.com/go-openssl/pkcs12"
)

type Option func(*Openssl) error

func WithHash(hash crypto.Hash) Option {
	return func(o *Openssl) error {
		o.hash = hash
		return nil
	}
}

func WithPrivateKey(privateKey *rsa.PrivateKey) Option {
	return func(o *Openssl) error {
		o.privateKey = privateKey
		return nil
	}
}

func WithPublicKey(publicKey *rsa.PublicKey) Option {
	return func(o *Openssl) error {
		o.publicKey = publicKey
		return nil
	}
}

func WithPrivateKeyText(privateKeyText []byte) Option {
	return func(o *Openssl) error {
		var err error
		o.privateKey, err = ParsePrivateKeyText(privateKeyText)
		return err
	}
}

func WithPublicKeyText(publicKeyText []byte) Option {
	return func(o *Openssl) error {
		var err error
		o.publicKey, err = ParsePublicKeyText(publicKeyText)
		return err
	}
}

func WithPfxFile(pfxFilePath, password string) Option {
	pfxFileText, err := os.ReadFile(pfxFilePath)
	if err != nil {
		return func(o *Openssl) error {
			return err
		}
	}
	return WithPfxFileText(pfxFileText, password)
}

func WithPfxFileText(pfxFileText []byte, password string) Option {
	return func(o *Openssl) error {
		pk, cert, err := pkcs12.Decode(pfxFileText, password)
		if err != nil {
			if err.Error() != "pkcs12: expected exactly two safe bags in the PFX PDU" {
				return err
			}
		}
		o.privateKey = pk.(*rsa.PrivateKey)
		o.publicKey = cert.PublicKey.(*rsa.PublicKey)
		return nil
	}
}

func WithCerFile(cerFilePath string) Option {
	cerFileText, err := os.ReadFile(cerFilePath)
	if err != nil {
		return func(o *Openssl) error {
			return err
		}
	}
	return WithCerFileText(cerFileText)
}

func WithCerFileText(cerFileText []byte) Option {
	return func(o *Openssl) error {
		cert, err := x509.ParseCertificate(cerFileText)
		if err != nil {
			return err
		}
		o.publicKey = cert.PublicKey.(*rsa.PublicKey)
		return nil
	}
}
