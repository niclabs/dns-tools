package signer

import (
	"crypto"
	"fmt"
	"github.com/miekg/pkcs11"
	"io"
)

// RRSignerECDSA Implements crypto.Signer Interface.
type RRSignerECDSA struct {
	Session *PKCS11Session      // PKCS#11 PKCS11Session
	SK, PK  pkcs11.ObjectHandle // Secret and Public Key handles
}

// Public returns the signer public key in the format RFC requires.
func (rs RRSignerECDSA) Public() crypto.PublicKey {
	return rs.PK
}

// Sign signs the content from the reader and returns a signature, or an error if it fails.
func (rs RRSignerECDSA) Sign(_ io.Reader, rr []byte, _ crypto.SignerOpts) ([]byte, error) {
	if rs.Session == nil || rs.Session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	mechanisms := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil),
	}
	err := rs.Session.P11Context.SignInit(rs.Session.Handle, mechanisms, rs.SK)
	if err != nil {
		return nil, err
	}
	sig, err := rs.Session.P11Context.Sign(rs.Session.Handle, rr)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
