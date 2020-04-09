package tools

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// FileSession represents a File session. It includes the context and a Label String,
// used in creation and retrieval of DNS keys.
type FileSession struct {
	ctx     *Context // HSM Tools Context
	zskFile io.ReadWriteSeeker
	kskFile io.ReadWriteSeeker
}

// Returns the session context
func (session *FileSession) Context() *Context {
	return session.ctx
}

func (session *FileSession) GetKeys() (keys *SigKeys, err error) {
	if session.ctx.Config.CreateKeys {
		session.ctx.Log.Printf("create-keys flag activated. Creating or overwriting keys")
		if err = session.generateKeys(); err != nil {
			return
		}
	}
	zsk, err := readerToPrivateKey(session.zskFile)
	if err != nil {
		return
	}
	ksk, err := readerToPrivateKey(session.kskFile)
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

// Writes new PKCS#8-formatted keys into the zsk and ksk files.
func (session *FileSession) generateKeys() (err error) {
	ctx := session.Context()
	var zskBytes, kskBytes []byte
	switch ctx.SignAlgorithm {
	case RSA_SHA256:
		kskBytes, err = session.generateRSAKey(2048)
		if err != nil {
			return
		}
		session.kskFile.Write(kskBytes)
		session.kskFile.Seek(0, io.SeekStart)
		zskBytes, err = session.generateRSAKey(1024)
		if err != nil {
			return
		}
		session.zskFile.Write(zskBytes)
		session.zskFile.Seek(0, io.SeekStart)
	case ECDSA_P256_SHA256:
		kskBytes, err = session.generateECDSAKey()
		if err != nil {
			return
		}
		session.kskFile.Write(kskBytes)
		session.kskFile.Seek(0, io.SeekStart)
		zskBytes, err = session.generateECDSAKey()
		if err != nil {
			return
		}
		session.zskFile.Write(zskBytes)
		session.zskFile.Seek(0, io.SeekStart)
	default:
		err = fmt.Errorf("undefined sign algorithm")
		return
	}
	return
}

// returns a pkcs#8 formatted RSA key, ready to be written in a file
func (session *FileSession) generateRSAKey(bits int) ([]byte, error) {
	sk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}), nil
}

// returns a pkcs#8 formatted RSA key, ready to be written in a file
func (session *FileSession) generateECDSAKey() ([]byte, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(sk)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}), nil
}
