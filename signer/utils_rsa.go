package signer

import (
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/miekg/pkcs11"
	"time"
)

// generateRSAKeyPair creates a RSA key pair, or returns an error if it cannot create the key pair.
func generateRSAKeyPair(session *Session, tokenLabel string, tokenPersistent bool, expDate time.Time, bits int) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if session == nil || session.Ctx == nil {
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

	pubKey, privKey, err := session.Ctx.GenerateKeyPair(
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


// loadRSASigningKeys returns the bytes of the key identified by the handle in the format specified by RFC3110.
func loadRSASigningKeys(session *Session, args *SessionSignArgs) (err error) {
	zskBytes, err := getRSAKeyBytes(session, args.Keys.PublicKSK.Handle)
	if err != nil {
		return err
	}
	args.ZSK = CreateNewDNSKEY(
		args.Zone,
		256,
		RSA_SHA256, // RSA/SHA256 (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		args.MinTTL,
		base64.StdEncoding.EncodeToString(zskBytes),
	)

	kskBytes, err := getRSAKeyBytes(session, args.Keys.PublicKSK.Handle)
	if err != nil {
		return err
	}
	args.KSK = CreateNewDNSKEY(
		args.Zone,
		257,
		RSA_SHA256,           // RSA/SHA256 (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		args.MinTTL, // SOA -> minimum TTL
		base64.StdEncoding.EncodeToString(kskBytes),
	)
	return
}

func getRSAKeyBytes(session *Session, object pkcs11.ObjectHandle) ([]byte, error) {
	if session == nil || session.Ctx == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	var n uint32

	PKTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	}

	attr, err := session.Ctx.GetAttributeValue(session.Handle, object, PKTemplate)
	if err != nil {
		return nil, err
	}

	n = uint32(len(attr[0].Value))
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

	a = append(a, attr[0].Value...)
	a = append(a, attr[1].Value...)

	return a, nil

}

func createRSASigners(session *Session, args *SessionSignArgs) (crypto.Signer, crypto.Signer) {
	zskSigner := RRSignerRSA{
		Session: session,
		PK:      args.Keys.PublicZSK.Handle,
		SK:      args.Keys.PrivateZSK.Handle,
	}

	kskSigner := RRSignerRSA{
		Session: session,
		PK:      args.Keys.PublicKSK.Handle,
		SK:      args.Keys.PrivateKSK.Handle,
	}
	return zskSigner, kskSigner
}
