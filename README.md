# 一、快速开始
```shell
go get -u github.com/go-openssl/openssl
```
# 二、示例
#### 1、根据```PHP```实现```sign```
```php
openssl_sign($data, $sign, $privateKey, OPENSSL_ALGO_SHA256)
```
```go
package main

import (
    "crypto"
    "fmt"
    
    "github.com/go-openssl/openssl"
)

func main() {
    openSSL, err := openssl.New(
        openssl.WithHash(crypto.SHA256),
        openssl.WithPrivateKeyText([]byte("private-key-text")),
    )
    if err != nil {
        panic(err)
    }
	
    sign, err := openSSL.Sign("hello world")
    if err != nil {
        panic(err)
    }
	
    fmt.Println(sign)
}

```
#### 2、根据```PHP```实现```verify```
```php
openssl_verify($data, base64_decode($sign), $publicKey, OPENSSL_ALGO_SHA1)
```
```go
package main

import (
    "crypto"
    "fmt"
    
    "github.com/go-openssl/openssl"
)

func main() {
    openSSL, err := openssl.New(
        openssl.WithHash(crypto.SHA1),
        openssl.WithPublicKeyText([]byte("public-key-text")),
    )
    if err != nil {
        panic(err)
    }

    var sign string

    ok, err := openSSL.Verify("hello world", sign)
    if err != nil {
        panic(err)
    }

    fmt.Println(ok)
}
```
# 三、生成```.pfx```证书
```shell
openssl genrsa -out private_key.pem 2048
```
```shell
openssl req -new -key private_key.pem -out csr.csr
```
```shell
openssl x509 -req -days 3650 -in csr.csr -signkey private_key.pem -out certificate.pem
```
```shell
openssl pkcs12 -export -out certificate.pfx -inkey private_key.pem -in certificate.pem -password pass:123456
```
![](./certs/generate-cert.png)
