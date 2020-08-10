package tools

import (
	"crypto"
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	"github.com/miekg/pkcs11"
)

// PKCS11Session represents a PKCS#11 session. It includes the context, the session handle and a Label String,
// used in creation and retrieval of DNS keys.
type PKCS11Session struct {
	libPath    string               // Library Path
	ctx        *Context             // HSM Tools Context
	P11Context *pkcs11.Ctx          // PKCS#11 Context
	Handle     pkcs11.SessionHandle // PKCS11Session Handle
	Label      string               // Signature Label
	Key        string               // Signature key
}

// Context Returns the session context
func (session *PKCS11Session) Context() *Context {
	return session.ctx
}

// GetKeys get the public key string and private key habdler from HSM.
// returns an error, if any.
func (session *PKCS11Session) GetKeys() (keys *SigKeys, err error) {
	ctx := session.Context()
	if ctx.Config.CreateKeys { // If we want to create new keys
		err = session.DestroyAllKeys() // We destroy the previously created keys
		if err != nil {
			return
		}
		return session.newSigners() // And create them
	}
	keys, err = session.searchValidKeys()
	if err != nil {
		if err == ErrNoValidKeys { // There are no keys
			err = fmt.Errorf("no valid keys and --create-keys disabled." +
				"Try again using --create-keys flag")
		} else {
			err = fmt.Errorf("corrupted hsm state (%s)."+
				" Please reset the keys or create new ones with "+
				"--create-keys flag", err)
		}
	}
	return
}

// GetPublicKeyBytes returns bytestrings of public zsk and ksk keys.
func (session *PKCS11Session) GetPublicKeyBytes(keys *SigKeys) (zskBytes, kskBytes []byte, err error) {
	var keyFun func(signer crypto.Signer) ([]byte, error)
	ctx := session.Context()
	switch ctx.SignAlgorithm {
	case RsaSha256:
		keyFun = session.getRSAPubKeyBytes
	case EcdsaP256Sha256:
		keyFun = session.getECDSAPubKeyBytes
	default:
		err = fmt.Errorf("undefined sign algorithm")
		return
	}
	zskBytes, err = keyFun(keys.zskSigner)
	if err != nil {
		return
	}
	kskBytes, err = keyFun(keys.kskSigner)
	return
}

// DestroyAllKeys destroys all the keys using the rsaLabel defined in the session struct.
func (session *PKCS11Session) DestroyAllKeys() error {
	if session == nil || session.P11Context == nil {
		return fmt.Errorf("session not initialized")
	}
	deleteTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
	}
	objects, err := session.findObject(deleteTemplate)
	if err != nil {
		return err
	}
	if len(objects) > 0 {
		session.ctx.Log.Printf("SigKeys found. Deleting...\n")
		foundDeleteTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		}

		for _, object := range objects {
			attr, _ := session.P11Context.GetAttributeValue(session.Handle, object, foundDeleteTemplate)
			class := "unknown"
			if uint(attr[2].Value[0]) == pkcs11.CKO_PUBLIC_KEY {
				class = "public"
			} else if uint(attr[2].Value[0]) == pkcs11.CKO_PRIVATE_KEY {
				class = "private"
			}
			session.ctx.Log.Printf("Deleting key with rsaLabel=%s, id=%s and type=%s\n", string(attr[0].Value), string(attr[1].Value), class)

			if e := session.P11Context.DestroyObject(session.Handle, object); e != nil {
				session.ctx.Log.Printf("Destroy PKCS11Key failed %s\n", e)
			}
		}
	}
	return nil
}

// End finishes a session execution, logging out and clossing the session.
func (session *PKCS11Session) End() error {
	if session.P11Context == nil {
		return fmt.Errorf("session not initialized")
	}
	if err := session.P11Context.Logout(session.Handle); err != nil {
		return err
	}
	if err := session.P11Context.CloseSession(session.Handle); err != nil {
		return err
	}
	if err := session.P11Context.Finalize(); err != nil {
		return err
	}
	session.P11Context.Destroy()
	return nil
}

func (session *PKCS11Session) newSigners() (keys *SigKeys, err error) {
	keys = &SigKeys{}
	session.ctx.Log.Printf("generating zsk")
	public, private, err := session.generateKeyPair("zsk")
	if err != nil {
		return
	}
	keys.zskSigner = &PKCS11RRSigner{
		Session: session,
		PK:      public,
		SK:      private,
	}

	session.ctx.Log.Printf("generating ksk")
	public, private, err = session.generateKeyPair("ksk")
	if err != nil {
		return
	}
	keys.kskSigner = &PKCS11RRSigner{
		Session: session,
		PK:      public,
		SK:      private,
	}
	session.ctx.Log.Printf("keys generated")
	return
}

// generateKeyPair returns a public-private key handle pair of the signAlgorithm defined
// for the session.
func (session *PKCS11Session) generateKeyPair(label string) (pk, sk pkcs11.ObjectHandle, err error) {
	ctx := session.Context()
	switch ctx.SignAlgorithm {
	case RsaSha256:
		bitSize := 1024
		if label == "ksk" {
			bitSize = 2048
		}
		return session.genRSAKeyPair(label, bitSize)
	case EcdsaP256Sha256:
		return session.genECDSAKeyPair(label)
	default:
		err = fmt.Errorf("undefined sign algorithm")
		return
	}
}

// findObject returns an object from the HSM following an specific template.
// It returns at most 1024 objects.
// If it fails, it returns a null array and an error.
func (session *PKCS11Session) findObject(template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	if err := session.P11Context.FindObjectsInit(session.Handle, template); err != nil {
		return nil, err
	}
	obj, _, err := session.P11Context.FindObjects(session.Handle, 1024)
	if err != nil {
		return nil, err
	}
	if err := session.P11Context.FindObjectsFinal(session.Handle); err != nil {
		return nil, err
	}
	return obj, nil
}

// searchValidKeys returns an array with the valid keys stored in the HSM.
func (session *PKCS11Session) searchValidKeys() (*SigKeys, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	AllTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
	}
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}
	objects, err := session.findObject(AllTemplate)
	if err != nil {
		return nil, err
	}

	zskSigner := &PKCS11RRSigner{
		Session: session,
	}
	kskSigner := &PKCS11RRSigner{
		Session: session,
	}
	validKeys := &SigKeys{
		kskSigner: kskSigner,
		zskSigner: zskSigner,
	}
	found := 0
	for _, object := range objects {
		attr, err := session.P11Context.GetAttributeValue(session.Handle, object, keyTemplate)
		if err != nil {
			return nil, fmt.Errorf("cannot get attributes: %s", err)
		}
		class := uint(binary.LittleEndian.Uint32(attr[0].Value))
		id := string(attr[1].Value)

		session.ctx.Log.Printf("Checking key class=%v and id=%s", class, id)

		if class == pkcs11.CKO_PUBLIC_KEY {
			if id == "zsk" {
				session.ctx.Log.Printf("Found Public ZSK")
				zskSigner.PK = object
				found++
			}
			if id == "ksk" {
				session.ctx.Log.Printf("Found valid Public KSK")
				kskSigner.PK = object
				found++
			}
		} else if class == pkcs11.CKO_PRIVATE_KEY {
			if id == "zsk" {
				session.ctx.Log.Printf("Found valid Private ZSK\n")
				zskSigner.SK = object
				found++
			} else if id == "ksk" {
				session.ctx.Log.Printf("Found valid Private KSK\n")
				kskSigner.SK = object
				found++
			}
		}
	}
	switch {
	case found == 0:
		return validKeys, ErrNoValidKeys
	case found == 4:
		return validKeys, nil
	case found > 4:
		return nil, fmt.Errorf("more keys (%d) than expected (4)", found)
	default:
		return nil, fmt.Errorf("less keys (%d) than expected (4)", found)
	}
}

// genRSAKeyPair creates a RSA key pair, or returns an error if it cannot create the key pair.
func (session *PKCS11Session) genRSAKeyPair(tokenLabel string, bits int) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if session == nil || session.P11Context == nil {
		return 0, 0, fmt.Errorf("session not initialized")
	}
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
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

// genECDSAKeyPair creates a ECDSA key pair, or returns an error if it cannot create the key pair.
func (session *PKCS11Session) genECDSAKeyPair(tokenLabel string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if session == nil || session.P11Context == nil {
		return 0, 0, fmt.Errorf("session not initialized")
	}
	ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}) // P-256 params
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(tokenLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
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
