package signer

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"github.com/miekg/pkcs11"
	"time"
)

// generatePKCS11RSAKeyPair creates a RSA key pair, or returns an error if it cannot create the key pair.
func generatePKCS11RSAKeyPair(session *PKCS11Session, tokenLabel string, tokenPersistent bool, expDate time.Time, bits int) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if session == nil || session.P11Context == nil {
		return 0, 0, fmt.Errorf("session not initialized")
	}
	today := time.Now()
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_START_DATE, today),
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, expDate),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_START_DATE, today),
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, expDate),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	}

	pubKey, privKey, err := session.P11Context.GenerateKeyPair(
		session.Handle,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return 0, 0, err
	}
	return pubKey, privKey, nil
}

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

// generateECDSAKeyPair creates a ECDSA key pair, or returns an error if it cannot create the key pair.
func generateECDSAKeyPair(session *PKCS11Session, tokenLabel string, tokenPersistent bool, expDate time.Time) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if session == nil || session.P11Context == nil {
		return 0, 0, fmt.Errorf("session not initialized")
	}
	today := time.Now()
	ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}) // P-256 params
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_START_DATE, today),
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, expDate),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_START_DATE, today),
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, expDate),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	}

	pubKey, privKey, err := session.P11Context.GenerateKeyPair(
		session.Handle,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil),
		},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return 0, 0, err
	}
	return pubKey, privKey, nil
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
