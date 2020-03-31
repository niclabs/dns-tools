package signer

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
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
	ctx := session.Context()
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ctx.Label),
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
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ctx.Label),
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

func (session *PKCS11Session) getRSAPubKeyBytes(key *PKCS11RRSigner) ([]byte, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	var n uint32

	PKTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	}

	attr, err := session.P11Context.GetAttributeValue(session.Handle, key.PK, PKTemplate)
	if err != nil {
		return nil, err
	}
	expVal := attr[0].Value
	if len(expVal) > 8 {
		return nil, fmt.Errorf("exponent length is larger than 8 bits")
	}
	v := make([]byte, 8)
	copy(v[8-len(expVal):], expVal)
	for v[0] == 0 {
		v = v[1:]
		if len(v) == 0 {
			return nil, fmt.Errorf("exponent is zero")
		}
	}
	n = uint32(len(v))
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, n)
	// Stores as BigEndian, read as LittleEndian, what could go wrong?
	if n < 256 {
		a = a[3:]
	} else if n <= 512 {
		a = a[1:]
	} else {
		return nil, fmt.Errorf("invalid exponent length. Its size must be between 1 and 4096 bits")
	}

	a = append(a, v...)
	a = append(a, attr[1].Value...)

	return a, nil

}


// generateECDSAKeyPair creates a ECDSA key pair, or returns an error if it cannot create the key pair.
func generateECDSAKeyPair(session *PKCS11Session, tokenLabel string, tokenPersistent bool, expDate time.Time) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if session == nil || session.P11Context == nil {
		return 0, 0, fmt.Errorf("session not initialized")
	}
	today := time.Now()
	ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}) // P-256 params
	ctx := session.Context()
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ctx.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_START_DATE, today),
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, expDate),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ctx.Label),
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

func (session *PKCS11Session) getECDSAPubKeyBytes(key *PKCS11RRSigner) ([]byte, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	PKTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attr, err := session.P11Context.GetAttributeValue(session.Handle, key.PK, PKTemplate)
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
