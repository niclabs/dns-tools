package signer

import (
	"crypto"
	"fmt"
	"github.com/miekg/pkcs11"
)

func (session *PKCS11Session) getRSAPubKeyBytes(signer crypto.Signer) ([]byte, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	key, ok := signer.(*PKCS11RRSigner)
	if !ok {
		return nil, fmt.Errorf("wrong signer provided. It should be of *PKCS11RRSigner type")
	}
	PKTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	}

	attr, err := session.P11Context.GetAttributeValue(session.Handle, key.PK, PKTemplate)
	if err != nil {
		return nil, err
	}
	if len(attr) != 2 {
		return nil, fmt.Errorf("wrong number of attributes received (%d). Expected 2", len(attr))
	}
	exponent := attr[0].Value
	modulus := attr[1].Value
	return rsaPublicKeyToBytes(exponent, modulus)
}

func (session *PKCS11Session) getECDSAPubKeyBytes(signer crypto.Signer) ([]byte, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	PKTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	key, ok := signer.(*PKCS11RRSigner)
	if !ok {
		return nil, fmt.Errorf("wrong signer provided. It should be of *PKCS11RRSigner type")
	}
	attr, err := session.P11Context.GetAttributeValue(session.Handle, key.PK, PKTemplate)
	if err != nil {
		return nil, err
	}
	if len(attr) == 0 {
		return nil, fmt.Errorf("Attribute not found")
	}
	// asn1 -> elliptic-marshaled
	return ecdsaPublicKeyToBytes(attr[0].Value)
}
