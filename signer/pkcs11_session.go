package signer

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"github.com/miekg/pkcs11"
	"time"
)

// PKCS11Session represents a PKCS#11 session. It includes the context, the session handle and a Label String,
// used in creation and retrieval of DNS keys.
type PKCS11Session struct {
	ctx           *Context             // HSM Tools Context
	P11Context    *pkcs11.Ctx          // PKCS#11 Context
	Handle        pkcs11.SessionHandle // PKCS11Session Handle
	Label         string // Signature Label
	Key           string // Signature key
}

// Returns the session context
func (session *PKCS11Session) Context() *Context {
	return session.ctx
}



// GetKeys get the public key string and private key habdler from HSM.
// returns an error, if any.
func (session *PKCS11Session) GetKeys() (keys *SigKeys, err error) {
	ctx := session.Context()
	keys, err = session.searchValidKeys()
	if err != nil {
		if err == NoValidKeys {
			if !ctx.CreateKeys {
				err = fmt.Errorf("no valid keys and --create-keys disabled." +
					"Try again using --create-keys flag")
				return
			}
		} else {
			err = fmt.Errorf("corrupted hsm state (%s)."+
				" Please reset the keys or create new ones with "+
				"--create-keys flag", err)
			return
		}
	}
	if ctx.CreateKeys {
		if err = session.expireKeys(keys); err != nil {
			return
		}
		if err = session.generateKeys(keys); err != nil {
			return
		}
	}
	return
}

// Returns bytestrings of public zsk and ksk keys.
func (session *PKCS11Session) GetPublicKeyBytes(keys *SigKeys) (zskBytes, kskBytes []byte, err error) {
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
	} else {
		return nil
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

func (session *PKCS11Session) expireKeys(keys *SigKeys) error {
	if keys == nil {
		return nil
	}
	err := session.expirePKCS11Key(keys.zskSigner)
	if err != nil {
		return err
	}
	return session.expirePKCS11Key(keys.kskSigner)
}

func (session *PKCS11Session) generateKeys(keys *SigKeys) error {
	defaultExpDate := time.Now().AddDate(1, 0, 0) // TODO: allow to config this?
	session.ctx.Log.Printf("generating zsk")
	public, private, err := session.generateKeyPair(
		"zsk",
		true,
		defaultExpDate)
	if err != nil {
		return err
	}
	keys.zskSigner = &PKCS11RRSigner{
		Session: session,
		PK:      public,
		SK:      private,
		ExpDate: defaultExpDate,
	}

	session.ctx.Log.Printf("generating ksk")
	public, private, err = session.generateKeyPair(
		"ksk",
		true,
		defaultExpDate)
	if err != nil {
		return err
	}
	keys.kskSigner = &PKCS11RRSigner{
		Session: session,
		PK:      public,
		SK:      private,
		ExpDate: defaultExpDate,
	}
	session.ctx.Log.Printf("keys generated")
	return nil
}

// generateKeyPair returns a public-private key handle pair of the signAlgorithm defined
// for the session.
func (session *PKCS11Session) generateKeyPair(label string, tokenPersistent bool, expDate time.Time) (pk, sk pkcs11.ObjectHandle, err error) {
	ctx := session.Context()
	switch ctx.SignAlgorithm {
	case RSA_SHA256:
		bitSize := 1024
		if label == "ksk" {
			bitSize = 2048
		}
		return generatePKCS11RSAKeyPair(
			session,
			label,
			tokenPersistent,
			expDate,
			bitSize,
		)
	case ECDSA_P256_SHA256:
		return generateECDSAKeyPair(
			session,
			label,
			tokenPersistent,
			expDate,
		)
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
	return removeDuplicates(obj), nil
}

// searchValidKeys returns an array with the valid keys stored in the HSM.
func (session *PKCS11Session) searchValidKeys() (*SigKeys, error) {
	if session == nil || session.P11Context == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	AllTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
	}

	DateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_START_DATE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	objects, err := session.findObject(AllTemplate)
	if err != nil {
		return nil, err
	}

	// I'm not sure if objects start at 0 or 1, so
	// I'm adding a boolean to tell if that key is present
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
	t := time.Now()
	sToday := t.Format("20060102")
	for _, object := range objects {
		attr, err := session.P11Context.GetAttributeValue(session.Handle, object, DateTemplate)
		if err != nil {
			return nil, fmt.Errorf("cannot get attributes: %s\n", err)
		} else {
			class := uint(binary.LittleEndian.Uint32(attr[0].Value))
			id := string(attr[1].Value)
			start := string(attr[2].Value)
			end := string(attr[3].Value)
			valid := start <= sToday && sToday <= end
			endTime, _ := time.Parse("20060102", end)

			session.ctx.Log.Printf("Checking key class %v id %s and valid %t\n", class, id, valid)

			if !valid {
				continue
			}

			if class == pkcs11.CKO_PUBLIC_KEY {
				if id == "zsk" {
					if valid {
						session.ctx.Log.Printf("Found valid Public ZSK")
						zskSigner.ExpDate = endTime
						zskSigner.PK = object
						found++
					}
				}
				if id == "ksk" {
					if valid {
						session.ctx.Log.Printf("Found valid Public KSK")
						kskSigner.ExpDate = endTime
						kskSigner.PK = object
						found++
					}
				}
			} else if class == pkcs11.CKO_PRIVATE_KEY {
				if id == "zsk" {
					session.ctx.Log.Printf("Found valid Private ZSK\n")
					zskSigner.ExpDate = endTime
					zskSigner.SK = object
					found++
				} else if id == "ksk" {
					session.ctx.Log.Printf("Found valid Private KSK\n")
					kskSigner.ExpDate = endTime
					kskSigner.SK = object
					found++
				}
			}
		}
	}
	switch {
	case found == 0:
		return validKeys, NoValidKeys
	case found == 4:
		return validKeys, nil
	case found > 4:
		return nil, fmt.Errorf("more keys (%d) than expected (4)", found)
	default:
		return nil, fmt.Errorf("less keys (%d) than expected (4)", found)
	}
}

// expirePKCS11Key expires a key into the HSM.
func (session *PKCS11Session) expirePKCS11Key(signer crypto.Signer) error {
	pkcs11Signer, ok := signer.(*PKCS11RRSigner)
	if !ok {
		return fmt.Errorf("cannot convert signer into PKCS11RRSigner")
	}
	today := time.Now()
	yesterday := today.AddDate(0, 0, -1)

	expireTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, yesterday),
	}
	if pkcs11Signer.PK != 0 {
		if err := session.P11Context.SetAttributeValue(session.Handle, pkcs11Signer.PK, expireTemplate); err != nil {
			return err
		}
	}
	if pkcs11Signer.SK != 0 {
		return session.P11Context.SetAttributeValue(session.Handle, pkcs11Signer.SK, expireTemplate)
	}
	return nil
}

