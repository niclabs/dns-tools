package signer

import (
	"crypto"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"github.com/miekg/pkcs11"
	"time"
)

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

func getECDSAPubKeyBytes(session *PKCS11Session, object pkcs11.ObjectHandle) ([]byte, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	PKTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attr, err := session.P11Context.GetAttributeValue(session.Handle, object, PKTemplate)
	if err != nil {
		return nil, err
	}
	if len(attr) == 0 {
		return nil, fmt.Errorf("Attribute not found")
	}
	// asn1 -> elliptic-marshaled
	asn1Encoded := make([]byte, 0)
	rest, err := asn1.Unmarshal(attr[0].Value, &asn1Encoded)
	if len(rest) > 0 {
		return nil, fmt.Errorf("corrupted public key")
	}
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), asn1Encoded)
	if x == nil {
		return nil, fmt.Errorf("error decoding point")
	}
	// elliptic-marshaled -> elliptic.pubkey
	bytesPoint := make([]byte, 64) // two 32 bit unsigned numbers
	xBytes, yBytes := x.Bytes(), y.Bytes()
	copy(bytesPoint[32-len(xBytes):32], xBytes)
	copy(bytesPoint[64-len(yBytes):64], yBytes)
	return bytesPoint, nil
	// elliptic.pubkey -> {x|y}
}

func createECDSASigners(session *PKCS11Session, keys *SignatureKeys) (crypto.Signer, crypto.Signer) {
	zskSigner := RRSignerECDSA{
		Session: session,
		PK:      keys.PublicZSK.Handle,
		SK:      keys.PrivateZSK.Handle,
	}

	kskSigner := RRSignerECDSA{
		Session: session,
		PK:      keys.PublicKSK.Handle,
		SK:      keys.PrivateKSK.Handle,
	}
	return zskSigner, kskSigner
}
