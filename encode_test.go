package openssl_test

import (
	"testing"
)

func TestEncodePrivateKey(t *testing.T) {
	bytes := openSSL.EncodePrivateKey("PRIVATE KEY", nil)
	if bytes == nil {
		t.Fatal("Encode private key fail.")
		return
	}
	t.Log(string(bytes))
}

func TestEncodePublicKey(t *testing.T) {
	bytes := openSSL.EncodePublicKey("PUBLIC KEY", nil)
	if bytes == nil {
		t.Fatal("Encode public key fail.")
		return
	}
	t.Log(string(bytes))
}
