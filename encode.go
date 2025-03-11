package openssl

import (
	"crypto/x509"
	"encoding/pem"
)

func (o *Openssl) EncodePrivateKey(typ string, header map[string]string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    typ,
		Headers: header,
		Bytes:   x509.MarshalPKCS1PrivateKey(o.privateKey),
	})
}

func (o *Openssl) EncodePublicKey(typ string, header map[string]string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    typ,
		Headers: header,
		Bytes:   x509.MarshalPKCS1PublicKey(o.publicKey),
	})
}
