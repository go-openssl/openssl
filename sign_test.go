package openssl_test

import (
	"crypto"
	"testing"

	"github.com/go-openssl/openssl"
)

const PrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvSa9KsScy+ZuFTiPLE7ZwMacmxmA6A8fu0jiPluliLwutgRO
TTZp3g9HmW1CuYt+ZoQH9t0JzHHNFu9yCetJdt5TrpQx9bBovTsh8h/ZQOPsyo0p
nKqi5G3x1Azvbzs6yTU8voz6xVT90/DVJcd71osTsn+7ajEZccfa35tl5DBdF95t
hWeyMz5p6ayFMUEU10HBUYmYTUzi4dvXcZUZvLOIOPMHoCTXcX98EmGqUvsLWpx8
mscaA5llZMg+ZXnT5OH+HW9ncfz7DqXiON3yo1BrNPdmN+Y4SI9dWrADUzGJO6u5
8OwncCphUsYqnlG2jd4n0JhjpA2WGD4c6zqJJQIDAQABAoIBAAOmqMYXj3M8Gmnc
cp8HUpqu+rzfrCZOjG1ABeXwPOy7vScURDKnVznLD7W9bylHsQPnjoPMVnEUzUGh
E5FvcjaSKglXoPM+GXd1mb0jsjzXaW2rdd8pSAWivaU7Lq/187eIiIihDgIbFt8t
ad/VzuUgQBwU7RgqpHQWyHnCdSAHanV6TDDzRssJPdVBVLHOgmiMthSw8OtJiXy7
p8oKVsMiLk/+nNKXBorpx4EhYdB4u+XreMBChLT/AYQfZ6Q9xvAVoRnSaFplvqNw
Xlxwo0T5tMZLla4QafZ+fQM9GvDudv2NebHvDbL6zTefthCYDK8utaQpcnm70WBp
NFdOuW0CgYEA4EAmFxhdop7T+iLcG4LMXAGhvyEmArtQftsfUKcuYV/vXbsX0pj/
64WmriVfFhyW+d27ZrDZ0knT9in6zfxER3mAigVvd5SJ2co10HiiIRNfMZKXjc3g
pKukPAw0fsrBhp1Cdml649RZnTdl7FaUs6xmWIszQi2fUca8HlF3wBMCgYEA1+5v
WTV+rcVh9qhs2y8feuWWkmYDVZMbmgE+V+bo4o/6T7FGGKen1EGWV46GiVBix31p
WSfMTOIZ7BEhRMU0GH0TGSM6yqsKF4Qu8jg9fxKt4tEMrPmvw/+VoHN+HLV790hP
G5Q+I2zDknCWvoWkEDC3y3O4YPh/Cpif/ubZ6OcCgYAePchlOO33rj+b7fOM6jiw
969eXRQJLkWOtfIlKEaC7zMSitaNmgB5PI7b0UJfcv+RNqu9D4BwcXBaNBMUkD6M
/P+unUkI8Ukdy70yHfKPT1N5FfHGN8thqZv+VQ8HQkSS6MY7vcHK06o6H2xpUMvA
5zDuI+eHtytTFd/snsPtbQKBgCFM8TklydqMtTXv9ZG767PtUlJTjzIUVM5kYLP3
tXSzVZwSr8e/m19dmgz4uwDUN9eiHKwWOiilOfAxGBtd+lHIgDiBOWDmDdFgnkjW
qY0+WTjAmp7WhufIM9Ah35IX3v1c1m5fZ1HZRTQBTw4k2A9zI/UpbIbv68+7h/ks
qvCDAoGAF0jwXqwZu0CJB+ojr6dawYXNalEKH7bMPyItdHK4PqWcftHjYXQthnQC
uOeS4tEa3nfahGhp68U9N18L3h3gkkHqIGJvPzAEIjaIeghkQ73RinA/94ZlUBm4
jVGL8OEtfrm3O6ukVFTaiBMXPwAN4e3qfkXuyRepN0DjUthymes=
-----END RSA PRIVATE KEY-----
`

const PublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSa9KsScy+ZuFTiPLE7Z
wMacmxmA6A8fu0jiPluliLwutgROTTZp3g9HmW1CuYt+ZoQH9t0JzHHNFu9yCetJ
dt5TrpQx9bBovTsh8h/ZQOPsyo0pnKqi5G3x1Azvbzs6yTU8voz6xVT90/DVJcd7
1osTsn+7ajEZccfa35tl5DBdF95thWeyMz5p6ayFMUEU10HBUYmYTUzi4dvXcZUZ
vLOIOPMHoCTXcX98EmGqUvsLWpx8mscaA5llZMg+ZXnT5OH+HW9ncfz7DqXiON3y
o1BrNPdmN+Y4SI9dWrADUzGJO6u58OwncCphUsYqnlG2jd4n0JhjpA2WGD4c6zqJ
JQIDAQAB
-----END PUBLIC KEY-----
`

var openSSL *openssl.Openssl

func init() {
	var err error
	if openSSL, err = openssl.New(
		openssl.WithHash(crypto.SHA256),
		openssl.WithPrivateKeyText([]byte(PrivateKey)),
		openssl.WithPublicKeyText([]byte(PublicKey)),
	); err != nil {
		panic(err)
	}

	if openSSL, err = openssl.New(
		openssl.WithHash(crypto.SHA1),
		openssl.WithPfxFile("./certs/private.pfx", "123456"),
		openssl.WithCerFile("./certs/public.cer"),
	); err != nil {
		panic(err)
	}
}

func TestSign(t *testing.T) {
	str := "hello world"
	sign, err := openSSL.Sign(str)
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(sign)
}
