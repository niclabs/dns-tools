package signer

import (
	"crypto"
	"fmt"
	"io"
)

// FileSession represents a File session. It includes the context and a Label String,
// used in creation and retrieval of DNS keys.
type FileSession struct {
	ctx       *Context // HSM Tools Context
	zskReader io.Reader
	kskReader io.Reader
}

// Returns the session context
func (session *FileSession) Context() *Context {
	return session.ctx
}

func (session *FileSession) GetKeys() (keys *SigKeys, err error) {
	zsk, err := readerToPrivateKey(session.zskReader)
	if err != nil {
		return
	}
	ksk, err := readerToPrivateKey(session.kskReader)
	if err != nil {
		return
	}
	return &SigKeys{
		zskSigner: &FileRRSigner{
			Session: session,
			Key:     zsk,
		},
		kskSigner: &FileRRSigner{
			Session: session,
			Key:     ksk,
		},
	}, nil
}

func (session *FileSession) GetPublicKeyBytes(keys *SigKeys) (zskBytes, kskBytes []byte, err error) {
	var keyFun func(signer crypto.Signer) ([]byte, error)
	ctx := session.Context()
	switch ctx.SignAlgorithm {
	case RSA_SHA256:
		keyFun = session.getRSAPubKeyBytes
	case ECDSA_P256_SHA256:
		keyFun = session.getECDSAPubKeyBytes
	default:
		err = fmt.Errorf("undefined sign algorithm")
		return
	}
	kskBytes, err = keyFun(keys.kskSigner)
	if err != nil {
		return
	}
	zskBytes, err = keyFun(keys.zskSigner)
	return
}

func (session *FileSession) DestroyAllKeys() error {
	return nil
}

func (session *FileSession) End() error {
	return nil
}
