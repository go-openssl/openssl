package openssl_test

import (
	"testing"
)

func TestVerify(t *testing.T) {
	str := "hello world"
	sign, err := openSSL.Sign(str)
	if err != nil {
		t.Fatal(err)
		return
	}
	ok, err := openSSL.Verify(str, sign)
	if err != nil {
		t.Fatal(err)
		return
	}
	if !ok {
		t.Fatal("verify failed")
		return
	}
}
