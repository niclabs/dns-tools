package signer

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

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

// NewPKCS11Session creates a new session.
// The arguments also define the HSM user key and the rsaLabel the keys will use when created or retrieved.
func (ctx *Context) NewFileSession(zsk, ksk io.Reader) (Session, error) {

}

// FileSign signs a zone with two key files.
func (ctx *Context) FileSign(ksk, zsk io.Reader) (err error) {
	if err = ctx.ReadAndParseZone(true); err != nil {
		return err
	}
	ctx.AddNSEC13()
	session, err := ctx.NewFileSession(ksk, zsk)
	if err != nil {
		return err
	}
	defer session.End()
	/* SIGN MY ANGLE OF MUSIC! */
	if _, err := session.Sign(); err != nil {
		return err
	}
	return nil
}
