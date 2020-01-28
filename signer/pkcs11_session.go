package signer

import (
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
	"sort"

	"time"
)

// PKCS11Session represents a PKCS#11 session. It includes the context, the session handle and a Label String,
// used in creation and retrieval of DNS keys.
type PKCS11Session struct {
	*Context             // HSM Tools Context
	P11Context *pkcs11.Ctx          // PKCS#11 Context
	Handle     pkcs11.SessionHandle // PKCS11Session Handle
	SignAlgorithm SignAlgorithm
}

// Key represents a structure with a handle and an expiration date.
type Key struct {
	Handle  pkcs11.ObjectHandle // Handle related with the key
	ExpDate time.Time           // Expiration Date of the key
}

// SignatureKeys contains the four keys used in zone signing.
type SignatureKeys struct {
	PublicZSK, PrivateZSK *Key
	PublicKSK, PrivateKSK *Key
}


// Sign signs a zone file and outputs the result into out path (if its length is more than zero).
// It also dumps the new signed filezone to the standard output.
func (session *PKCS11Session) Sign() (ds *dns.DS, err error) {

	keys, err := session.getKeys()
	if err != nil {
		return nil, err
	}

	session.Log.Printf("Start signing...\n")
	zskSigner, kskSigner, err := session.createSigners(keys)
	if err != nil {
		return nil, err
	}
	rrSet := session.RRs.createRRSet(session.Zone, true)

	// ok, we create DNSKEYS
	zsk, ksk, err := session.getDNSKEY(keys)
	if err != nil {
		return nil, err
	}

	for _, v := range rrSet {
		rrSig := CreateNewRRSIG(session.Zone,
			zsk,
			session.SignExpDate,
			v[0].Header().Ttl)
		err = rrSig.Sign(zskSigner, v)
		if err != nil {
			err = fmt.Errorf("cannot sign RRSig: %s", err)
			return nil, err
		}
		err = rrSig.Verify(zsk, v)
		if err != nil {
			err = fmt.Errorf("cannot check RRSig: %s", err)
			return nil, err
		}
		session.RRs = append(session.RRs, rrSig)
	}

	rrDNSKeys := RRArray{zsk, ksk}

	rrDNSKeySig := CreateNewRRSIG(session.Zone,
		ksk,
		session.SignExpDate,
		ksk.Hdr.Ttl)
	err = rrDNSKeySig.Sign(kskSigner, rrDNSKeys)
	if err != nil {
		return nil, err
	}
	err = rrDNSKeySig.Verify(ksk, rrDNSKeys)
	if err != nil {
		err = fmt.Errorf("cannot check ksk RRSig: %s", err)
		return nil, err
	}

	session.RRs = append(session.RRs, zsk, ksk, rrDNSKeySig)

	sort.Sort(session.RRs)
	ds = ksk.ToDS(1)
	session.Log.Printf("DS: %s\n", ds) // SHA256
	err = session.RRs.writeZone(session.Output)
	return ds, err
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

// DestroyAllKeys destroys all the keys using the label defined in the session struct.
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
		session.Log.Printf("SigKeys found. Deleting...\n")
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
			session.Log.Printf("Deleting key with label=%s, id=%s and type=%s\n", string(attr[0].Value), string(attr[1].Value), class)

			if e := session.P11Context.DestroyObject(session.Handle, object); e != nil {
				session.Log.Printf("Destroy Key failed %s\n", e)
			}
		}
	} else {
		return fmt.Errorf("no keys found")
	}
	return nil
}

// getKeys get the public key string and private key habdler from HSM.
// returns an error, if any.
func (session *PKCS11Session) getKeys() (keys *SignatureKeys, err error) {
	keys, err = session.searchValidKeys()
	if err != nil {
		return
	}
	if session.CreateKeys {
		if err = session.expireKeys(keys); err != nil {
			return
		}
		if err = session.generateKeys(keys); err != nil {
			return
		}
	}
	if keys.PublicZSK == nil || keys.PublicKSK == nil {
		err = fmt.Errorf(
			"valid keys not found. If you have not keys stored " +
				"in the HSM, you can create a new pair with " +
				"--create-keys flag",
		)
		return
	}
	return
}

func (session *PKCS11Session) getDNSKEY(keys *SignatureKeys) (zsk, ksk *dns.DNSKEY, err error) {
	zskBytes, err := session.getPubKeyBytes(keys.PublicZSK.Handle)
	if err != nil {
		return
	}
	zsk = CreateNewDNSKEY(
		session.Zone,
		256,
		uint8(session.SignAlgorithm), // (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		session.MinTTL,
		base64.StdEncoding.EncodeToString(zskBytes),
	)

	kskBytes, err := session.getPubKeyBytes(keys.PublicKSK.Handle)
	if err != nil {
		return
	}
	ksk = CreateNewDNSKEY(
		session.Zone,
		257,
		uint8(session.SignAlgorithm), // (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		session.MinTTL,                  // SOA -> minimum TTL
		base64.StdEncoding.EncodeToString(kskBytes),
	)
	return
}

func (session *PKCS11Session) getPubKeyBytes(object pkcs11.ObjectHandle) ([]byte, error) {
	switch session.SignAlgorithm {
	case RSA_SHA256:
		return getRSAPubKeyBytes(session, object)
	case ECDSA_P256_SHA256:
		return getECDSAPubKeyBytes(session, object)
	default:
		return nil, fmt.Errorf("undefined sign algorithm")
	}
}

func (session *PKCS11Session) expireKeys(keys *SignatureKeys) error {
	if keys.PublicZSK != nil {
		err := session.expireKey(keys.PublicZSK.Handle)
		if err != nil {
			return err
		}
	}
	if keys.PrivateZSK != nil {
		err := session.expireKey(keys.PrivateZSK.Handle)
		if err != nil {
			return err
		}
	}
	if keys.PublicKSK != nil {
		err := session.expireKey(keys.PublicKSK.Handle)
		if err != nil {
			return err
		}
	}
	if keys.PrivateKSK != nil {
		err := session.expireKey(keys.PrivateKSK.Handle)
		if err != nil {
			return err
		}
	}
	return nil
}

func (session *PKCS11Session) generateKeys(keys *SignatureKeys) error {
	defaultExpDate := time.Now().AddDate(1, 0, 0) // TODO: allow to config this?
	session.Log.Printf("generating zsk\n")
	public, private, err := session.generateKeyPair(
		"zsk",
		true,
		defaultExpDate)
	if err != nil {
		return err
	}
	keys.PublicZSK = &Key{
		Handle:  public,
		ExpDate: defaultExpDate,
	}
	keys.PrivateZSK = &Key{
		Handle:  private,
		ExpDate: defaultExpDate,
	}

	session.Log.Printf("generating ksk\n")
	public, private, err = session.generateKeyPair(
		"ksk",
		true,
		defaultExpDate)
	if err != nil {
		return err
	}
	keys.PublicKSK = &Key{
		Handle:  public,
		ExpDate: defaultExpDate,
	}
	keys.PrivateKSK = &Key{
		Handle:  private,
		ExpDate: defaultExpDate,
	}
	session.Log.Printf("keys generated.\n")
	return nil
}

func (session *PKCS11Session) generateKeyPair(label string, tokenPersistent bool, expDate time.Time) (pk, sk pkcs11.ObjectHandle, err error) {
	switch session.SignAlgorithm {
	case RSA_SHA256:
		bitSize := 1024
		if label == "ksk" {
			bitSize = 2048
		}
		return generateRSAKeyPair(
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

func (session *PKCS11Session) createSigners(keys *SignatureKeys) (zsk, ksk crypto.Signer, err error) {
	switch session.SignAlgorithm {
	case RSA_SHA256:
		zsk, ksk = createRSASigners(session, keys)
	case ECDSA_P256_SHA256:
		zsk, ksk = createECDSASigners(session, keys)
	default:
		err = fmt.Errorf("undefined sign algorithm")
	}
	return
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
func (session *PKCS11Session) searchValidKeys() (*SignatureKeys, error) {
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
	validKeys := &SignatureKeys{}
	if len(objects) > 0 {
		t := time.Now()
		sToday := t.Format("20060102")
		session.Log.Printf("SigKeys found... checking validity\n")
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

				session.Log.Printf("Checking key class %v id %s and valid %t\n", class, id, valid)

				if !valid {
					continue
				}

				if class == pkcs11.CKO_PUBLIC_KEY {
					if id == "zsk" {
						if valid {
							session.Log.Printf("Found valid Public ZSK\n")
							validKeys.PublicZSK = &Key{
								Handle:  object,
								ExpDate: endTime,
							}
						}
					}
					if id == "ksk" {
						if valid {
							session.Log.Printf("Found valid Public KSK\n")
							validKeys.PublicKSK = &Key{
								Handle:  object,
								ExpDate: endTime,
							}
						}
					}
				} else if class == pkcs11.CKO_PRIVATE_KEY {
					if id == "zsk" {
						session.Log.Printf("Found valid Private ZSK\n")
						validKeys.PrivateZSK = &Key{
							Handle:  object,
							ExpDate: endTime,
						}
					} else if id == "ksk" {
						session.Log.Printf("Found valid Private KSK\n")
						validKeys.PrivateKSK = &Key{
							Handle:  object,
							ExpDate: endTime,
						}
					}
				}
			}
		}
	}
	return validKeys, nil
}

// expireKey expires a key into the HSM.
func (session *PKCS11Session) expireKey(handle pkcs11.ObjectHandle) error {

	today := time.Now()
	yesterday := today.AddDate(0, 0, -1)

	expireTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, yesterday),
	}

	return session.P11Context.SetAttributeValue(session.Handle, handle, expireTemplate)
}
