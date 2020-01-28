package signer

import (
	"crypto"
	"fmt"
	"github.com/miekg/pkcs11"
	"io"
)

// This prefixes are used for PKCS#1 padding of signatures.
var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// RRSignerRSA Implements crypto.Signer Interface.
type RRSignerRSA struct {
	Session *PKCS11Session      // PKCS#11 PKCS11Session
	SK, PK  pkcs11.ObjectHandle // Secret and Public Key handles
}

// Public returns the signer public key.
func (rs RRSignerRSA) Public() crypto.PublicKey {
	return rs.PK
}

// Sign signs the content from the reader and returns a signature, or an error if it fails.
func (rs RRSignerRSA) Sign(rand io.Reader, rr []byte, opts crypto.SignerOpts) ([]byte, error) {
	if rs.Session == nil || rs.Session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	// Inspired in https://github.com/ThalesIgnite/crypto11/blob/38ef75346a1dc2094ffdd919341ef9827fb041c0/rsa.go#L281
	oid := pkcs1Prefix[opts.HashFunc()]
	T := make([]byte, len(oid)+len(rr))
	copy(T[0:len(oid)], oid)
	copy(T[len(oid):], rr)

	mechanisms := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
	}
	err := rs.Session.P11Context.SignInit(rs.Session.Handle, mechanisms, rs.SK)
	if err != nil {
		return nil, err
	}
	sig, err := rs.Session.P11Context.Sign(rs.Session.Handle, T)
	if err != nil {
		return nil, err
	}
	return sig, nil
}