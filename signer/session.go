package signer

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
	"io"
	"log"
	"sort"
	"time"
)

// Session represents a PKCS#11 session. It includes the context, the session handle and a Label String,
// used in creation and retrieval of DNS keys.
type Session struct {
	Ctx    *pkcs11.Ctx          // PKCS#11 Context
	Handle pkcs11.SessionHandle // Session Handle
	Label  string               // Key Label
	Log    *log.Logger          // Logger (for output)
}

// Key represents a structure with a handle and an expiration date.
type Key struct {
	Handle  pkcs11.ObjectHandle // Handle related with the key
	ExpDate time.Time           // Expiration Date of the key
}

// ValidKeys contains the four keys used in zone signing.
// bKeys = {pzsk, szsk, pksk, sksk}
type ValidKeys struct {
	PublicZSK, PrivateZSK *Key
	PublicKSK, PrivateKSK *Key
}

// SignArgs contains all the args needed to sign a file.
type SignArgs struct {
	Zone        string    // Zone name
	File        io.Reader // File path
	Output      io.Writer // Out path
	SignExpDate time.Time // Expiration date for the signature.
	CreateKeys  bool      // If True, the sign process creates new keys for the signature.
	NSEC3       bool      // If true, the zone is signed using NSEC3
	OptOut      bool      // If true and NSEC3 is true, the zone is signed using OptOut NSEC3 flag.
}

// NewSession creates a new session, using the pkcs#11 library defined in the arguments.
// The arguments also define the HSM user key and the label the keys will use when created or retrieved.
func NewSession(p11lib, key, label string, log *log.Logger) (*Session, error) {
	p := pkcs11.New(p11lib)
	if p == nil {
		return nil, fmt.Errorf("Error initializing %s: file not found\n", p11lib)
	}
	err := p.Initialize()
	if err != nil {
		return nil, fmt.Errorf("Error initializing %s: %s. (Has the .db RW permission?)\n", p11lib, err)
	}
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("Error checking slots: %s\n", err)
	}
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("Error creating session: %s\n", err)
	}
	err = p.Login(session, pkcs11.CKU_USER, key)
	if err != nil {
		return nil, fmt.Errorf("Error login with provided key: %s\n", err)
	}
	return &Session{
		Ctx:    p,
		Handle: session,
		Label:  label,
		Log:    log,
	}, nil
}

// End finishes a session execution, logging out and clossing the session.
func (session *Session) End() error {
	if session.Ctx == nil {
		return fmt.Errorf("session not initialized")
	}
	if err := session.Ctx.Logout(session.Handle); err != nil {
		return err
	}
	if err := session.Ctx.CloseSession(session.Handle); err != nil {
		return err
	}
	if err := session.Ctx.Finalize(); err != nil {
		return err
	}
	session.Ctx.Destroy()
	return nil
}

// DestroyAllKeys destroys all the keys using the label defined in the session struct.
func (session *Session) DestroyAllKeys() error {
	if session == nil || session.Ctx == nil {
		return fmt.Errorf("session not initialized")
	}
	deleteTemplate := []*pkcs11.Attribute{
		//NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, session.Label),
	}
	objects, err := session.FindObject(deleteTemplate)
	if err != nil {
		return err
	}
	if len(objects) > 0 {
		session.Log.Printf("Keys found. Deleting...\n")
		foundDeleteTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		}

		for _, object := range objects {
			attr, _ := session.Ctx.GetAttributeValue(session.Handle, object, foundDeleteTemplate)
			class := "unknown"
			if uint(attr[2].Value[0]) == pkcs11.CKO_PUBLIC_KEY {
				class = "public"
			} else if uint(attr[2].Value[0]) == pkcs11.CKO_PRIVATE_KEY {
				class = "private"
			}
			session.Log.Printf("Deleting key with label=%s, id=%s and type=%s\n", string(attr[0].Value), string(attr[1].Value), class)

			if e := session.Ctx.DestroyObject(session.Handle, object); e != nil {
				session.Log.Printf("Destroy Key failed %s\n", e)
			}
		}
	} else {
		return fmt.Errorf("no keys found")
	}
	return nil
}

// Sign signs a zone file and outputs the result into out path (if its length is more than zero).
// It also dumps the new signed filezone to the standard output.
func (session *Session) Sign(args *SignArgs) (ds *dns.DS, err error) {

	if args.Zone[len(args.Zone)-1] != '.' {
		args.Zone = args.Zone + "."
	}
	rrZone, minTTL, err := readAndParseZone(args.File, true)
	if err != nil {
		return
	}
	keys, err := session.SearchValidKeys()
	if err != nil {
		return
	}

	if args.CreateKeys {
		defaultExpDate := time.Now().AddDate(1, 0, 0)
		var public, private pkcs11.ObjectHandle
		if keys.PublicZSK != nil {
			err = session.ExpireKey(keys.PublicZSK.Handle)
			if err != nil {
				return
			}
		}
		if keys.PrivateZSK != nil {
			err = session.ExpireKey(keys.PrivateZSK.Handle)
			if err != nil {
				return
			}
		}
		session.Log.Printf("generating zsk\n")
		public, private, err = session.GenerateRSAKeyPair(
			"zsk",
			true,
			defaultExpDate,
			1024,
		)
		if err != nil {
			return
		}
		keys.PublicZSK = &Key{
			Handle:  public,
			ExpDate: defaultExpDate,
		}
		keys.PrivateZSK = &Key{
			Handle:  private,
			ExpDate: defaultExpDate,
		}

		if keys.PublicKSK != nil {
			err = session.ExpireKey(keys.PublicKSK.Handle)
			if err != nil {
				return
			}
		}
		if keys.PrivateKSK != nil {
			err = session.ExpireKey(keys.PrivateKSK.Handle)
			if err != nil {
				return
			}
		}
		session.Log.Printf("generating ksk\n")
		public, private, err = session.GenerateRSAKeyPair(
			"ksk",
			true,
			defaultExpDate,
			2048,
		)
		if err != nil {
			return
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
	}

	if keys.PublicZSK == nil || keys.PublicKSK == nil {
		err = fmt.Errorf(
			"valid keys not found. If you have not keys stored in the HSM," +
				" you can create a new pair with --create-keys flag",
		)
		return
	}

	zskBytes, err := session.GetKeyBytes(keys.PublicZSK.Handle)
	if err != nil {
		return
	}
	zsk := CreateNewDNSKEY(
		args.Zone,
		256,
		8, // RSA/SHA256 (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		minTTL,
		base64.StdEncoding.EncodeToString(zskBytes),
	)

	kskBytes, err := session.GetKeyBytes(keys.PublicKSK.Handle)
	if err != nil {
		return
	}
	ksk := CreateNewDNSKEY(
		args.Zone,
		257,
		8, // RSA/SHA256 (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		minTTL, // SOA -> minimum TTL
		base64.StdEncoding.EncodeToString(kskBytes),
	)

	if args.NSEC3 {
		for {
			if err := rrZone.AddNSEC3Records(args.OptOut); err == nil {
				break
			}
			session.Log.Printf("Collision detected, NSEC3-ing all again\n")
		}
	} else {
		rrZone.AddNSECRecords()
	}

	session.Log.Printf("Start signing...\n")
	zskSigner := RRSigner{
		Session: session,
		PK:      keys.PublicZSK.Handle,
		SK:      keys.PrivateZSK.Handle,
	}

	kskSigner := RRSigner{
		Session: session,
		PK:      keys.PublicKSK.Handle,
		SK:      keys.PrivateKSK.Handle,
	}

	rrSet := rrZone.CreateRRSet(true)

	for _, v := range rrSet {
		rrSig := CreateNewRRSIG(args.Zone, zsk, args.SignExpDate, v[0].Header().Ttl)
		err = rrSig.Sign(zskSigner, v)
		if err != nil {
			err = fmt.Errorf("cannot sign RRSig: %s", err)
			return
		}
		err = rrSig.Verify(zsk, v)
		if err != nil {
			err = fmt.Errorf("cannot check RRSig: %s", err)
			return
		}
		rrZone = append(rrZone, rrSig)
	}

	rrDNSKeys := RRArray{zsk, ksk}

	rrDNSKeySig := CreateNewRRSIG(args.Zone, ksk, args.SignExpDate, ksk.Hdr.Ttl)
	err = rrDNSKeySig.Sign(kskSigner, rrDNSKeys)
	if err != nil {
		return
	}
	err = rrDNSKeySig.Verify(ksk, rrDNSKeys)
	if err != nil {
		err = fmt.Errorf("cannot check ksk RRSig: %s", err)
		return
	}

	rrZone = append(rrZone, zsk, ksk, rrDNSKeySig)

	sort.Sort(rrZone)
	ds = ksk.ToDS(1)
	session.Log.Printf("DS: %s\n", ds) // SHA256
	err = rrZone.WriteZone(args.Output);
	return
}

// FindObject returns an object from the HSM following an specific template.
// It returns at most 1024 objects.
// If it fails, it returns a null array and an error.
func (session *Session) FindObject(template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if session == nil || session.Ctx == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	if err := session.Ctx.FindObjectsInit(session.Handle, template); err != nil {
		return nil, err
	}
	obj, _, err := session.Ctx.FindObjects(session.Handle, 1024)
	if err != nil {
		return nil, err
	}
	if err := session.Ctx.FindObjectsFinal(session.Handle); err != nil {
		return nil, err
	}
	return removeDuplicates(obj), nil
}

// GenerateRSAKeyPair creates a RSA key pair, or returns an error if it cannot create the key pair.
func (session *Session) GenerateRSAKeyPair(tokenLabel string, tokenPersistent bool, expDate time.Time, bits int) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
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

// GetKeyBytes returns the bytes of the key identified by the handle in the format specified by RFC3110.
func (session *Session) GetKeyBytes(object pkcs11.ObjectHandle) ([]byte, error) {
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

// SearchValidKeys returns an array with the valid keys stored in the HSM.
func (session *Session) SearchValidKeys() (*ValidKeys, error) {
	if session == nil || session.Ctx == nil {
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
	objects, err := session.FindObject(AllTemplate)
	if err != nil {
		return nil, err
	}

	// I'm not sure if objects start at 0 or 1, so
	// I'm adding a boolean to tell if that key is present
	validKeys := &ValidKeys{}
	if len(objects) > 0 {
		t := time.Now()
		sToday := t.Format("20060102")
		session.Log.Printf("Keys found... checking validity\n")
		for _, object := range objects {
			attr, err := session.Ctx.GetAttributeValue(session.Handle, object, DateTemplate)
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

// ExpireKey expires a key into the HSM.
func (session *Session) ExpireKey(handle pkcs11.ObjectHandle) error {

	today := time.Now()
	yesterday := today.AddDate(0, 0, -1)

	expireTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_END_DATE, yesterday),
	}

	return session.Ctx.SetAttributeValue(session.Handle, handle, expireTemplate)
}
