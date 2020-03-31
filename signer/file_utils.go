package signer

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

// readerToKeyPair transforms a reader into a RSA or ECDSA KeyPair
func readerToKeyPair(r io.Reader) (crypto.PublicKey, crypto.PrivateKey, error) {
	rawBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	pem, rest := pem.Decode(rawBytes)
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("File should only contain one key block")
	}
	if pem == nil {
		return nil, nil, fmt.Errorf("no valid blocks found")
	}
	switch pem.Type{
	case "RSA PRIVATE KEY":
		sk, err := x509.ParsePKCS1PrivateKey(pem.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return sk.Public(), sk, nil
	case "EC PRIVATE KEY":
		sk, err := x509.ParseECPrivateKey(pem.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return sk.Public(), sk, nil
	default:
		return nil, nil, fmt.Errorf("key not supported. It should be a RSA or EC private key only")
	}
}
