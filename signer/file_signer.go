package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
)

type FileRRSigner struct {
	Session Session
	Key     crypto.PrivateKey
}

func (signer *FileRRSigner) Public() crypto.PublicKey {
	ctx := signer.Session.Context()
	switch ctx.SignAlgorithm {
	case RSA_SHA256:
		rsaKey, ok := signer.Key.(*rsa.PrivateKey)
		if !ok {
			return nil
		}
		pubKey := rsaKey.Public()
		return pubKey
	case ECDSA_P256_SHA256:
		ecdsaKey, ok := signer.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil
		}
		return ecdsaKey.Public()
	}
	return nil
}

func (signer *FileRRSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := signer.Session.Context()
	switch ctx.SignAlgorithm {
	case RSA_SHA256:
		rsaKey, ok := signer.Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("wrong key type")
		}
		return rsaKey.Sign(rand, digest, opts)
	case ECDSA_P256_SHA256:
		ecdsaKey, ok := signer.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("wrong key type")
		}
		return ecdsaKey.Sign(rand, digest, opts)

	}
	return nil, fmt.Errorf("signAlgorithm not implemented")
}
