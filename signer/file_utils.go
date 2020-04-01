package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
)


// readerToKeyPair transforms a reader into a RSA or ECDSA KeyPair
func readerToPrivateKey(r io.Reader) (crypto.PrivateKey, error) {
	rawBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	pem, rest := pem.Decode(rawBytes)
	if len(rest) > 0 {
		return nil, fmt.Errorf("file should only contain one key block")
	}
	if pem == nil {
		return nil, fmt.Errorf("key file is empty. If you want to create new keys, use --create-keys flag")
	}
	switch pem.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(pem.Bytes)
	default:
		return nil, fmt.Errorf("key not supported. It should be a RSA or EC private key only")
	}
}

func (session *FileSession) getRSAPubKeyBytes(signer crypto.Signer) (bytes []byte, err error) {
	rrSigner, ok := signer.(*FileRRSigner)
	if !ok {
		return nil, fmt.Errorf("getRSAPubKeyBytes expected FileRRSigner")
	}
	pk, ok := rrSigner.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("getRSAPubKeyBytes expected RSA key")
	}
	exponent := make([]byte, reflect.TypeOf(pk.E).Size())
	binary.BigEndian.PutUint64(exponent, uint64(pk.E))
	for exponent[0] == 0 {
		exponent = exponent[1:]
		if len(exponent) == 0 {
			return nil, fmt.Errorf("exponent is zero")
		}
	}
	modulus := pk.N.Bytes()
	return rsaPublicKeyToBytes(exponent, modulus)
}

func (session *FileSession) getECDSAPubKeyBytes(signer crypto.Signer) (bytes []byte, err error) {
	rrSigner, ok := signer.(*FileRRSigner)
	if !ok {
		return nil, fmt.Errorf("getECDSAPubKeyBytes expected FileRRSigner")
	}
	pk, ok := rrSigner.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("getECDSAPubKeyBytes expected ECDSA key")
	}
	curveBytes := 2 * int((pk.Curve.Params().BitSize + 7) / 8)
	xBytes, yBytes := pk.X.Bytes(), pk.Y.Bytes()
	bytesPoint := make([]byte, curveBytes) // two 32 bit unsigned numbers
	copy(bytesPoint[curveBytes/2-len(xBytes):curveBytes/2], xBytes)
	copy(bytesPoint[curveBytes-len(yBytes):curveBytes], yBytes)
	return bytesPoint, nil
}
