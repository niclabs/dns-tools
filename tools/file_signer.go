package tools

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
)

type fileRRSigner struct {
	Session SignSession
	Key     crypto.PrivateKey
}

func (signer *fileRRSigner) Public() crypto.PublicKey {
	ctx := signer.Session.Context()
	switch ctx.SignAlgorithm {
	case RsaSha256:
		rsaKey, ok := signer.Key.(*rsa.PrivateKey)
		if !ok {
			return nil
		}
		pubKey := rsaKey.Public()
		return pubKey
	case EcdsaP256Sha256:
		ecdsaKey, ok := signer.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil
		}
		return ecdsaKey.Public()
	}
	return nil
}

func (signer *fileRRSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := signer.Session.Context()
	switch ctx.SignAlgorithm {
	case RsaSha256:
		rsaKey, ok := signer.Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("wrong key type")
		}
		return rsaKey.Sign(rand, digest, opts)
	case EcdsaP256Sha256:
		ecdsaKey, ok := signer.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("wrong key type")
		}
		return ecdsaKey.Sign(rand, digest, opts)

	}
	return nil, fmt.Errorf("signAlgorithm not implemented")
}
