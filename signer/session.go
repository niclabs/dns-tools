package signer

import (
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
	//	"io"
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
	SignAlgorithm
	Log *log.Logger // Logger (for output)
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
// SessionSignArgs extend it for the session
type SessionSignArgs struct {
	*SignArgs
	Keys *ValidKeys  // Signature keys
	ZSK  *dns.DNSKEY // ZSK
	KSK  *dns.DNSKEY // KSK
}

// NewSession creates a new session, using the pkcs#11 library defined in the arguments.
// The arguments also define the HSM user key and the label the keys will use when created or retrieved.
func NewSession(p11lib, key, label string, signAlgorithm string, log *log.Logger) (*Session, error) {
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
	algorithm, ok := StringToSignAlgorithm[signAlgorithm]
	if !ok {
		return nil, fmt.Errorf("error with provided sign algorithm: not found")
	}
	return &Session{
		Ctx:           p,
		Handle:        session,
		Label:         label,
		Log:           log,
		SignAlgorithm: algorithm,
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

// GetKeys get the public key string and private key habdler from HSM.
// returns an error, if any.
func (session *Session) GetKeys(args *SessionSignArgs) error {
	keys, err := session.SearchValidKeys()
	if err != nil {
		return err
	}

	if args.CreateKeys {
		if err := session.expireKeys(keys); err != nil {
			return err
		}
		if err := session.generateKeys(keys); err != nil {
			return err
		}
	}
	args.Keys = keys

	if args.Keys.PublicZSK == nil || args.Keys.PublicKSK == nil {
		err = fmt.Errorf(
			"valid keys not found. If you have not keys stored " +
				"in the HSM, you can create a new pair with " +
				"--create-keys flag",
		)
		return err
	}
	args.Keys = keys

	// ok, we create DNSKEYS
	return loadRSASigningKeys(session, args)
}

func (session *Session) expireKeys(keys *ValidKeys) error {
	if keys.PublicZSK != nil {
		err := session.ExpireKey(keys.PublicZSK.Handle)
		if err != nil {
			return err
		}
	}
	if keys.PrivateZSK != nil {
		err := session.ExpireKey(keys.PrivateZSK.Handle)
		if err != nil {
			return err
		}
	}
	return nil
}

func (session *Session) generateKeys(keys *ValidKeys) error {
	defaultExpDate := time.Now().AddDate(1, 0, 0) // TODO: allow to config this?
	session.Log.Printf("generating zsk\n")
	public, private, err := generateRSAKeyPair(
		session,
		"zsk",
		true,
		defaultExpDate,
		1024,
	)
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

	if keys.PublicKSK != nil {
		err = session.ExpireKey(keys.PublicKSK.Handle)
		if err != nil {
			return err
		}
	}
	if keys.PrivateKSK != nil {
		err = session.ExpireKey(keys.PrivateKSK.Handle)
		if err != nil {
			return err
		}
	}
	session.Log.Printf("generating ksk\n")
	public, private, err = generateRSAKeyPair(
		session,
		"ksk",
		true,
		defaultExpDate,
		2048,
	)
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

// Sign signs a zone file and outputs the result into out path (if its length is more than zero).
// It also dumps the new signed filezone to the standard output.
func (session *Session) Sign(args *SessionSignArgs) (ds *dns.DS, err error) {

	session.Log.Printf("Start signing...\n")
	zskSigner, kskSigner := createRSASigners(session, args)

	rrSet := args.RRs.CreateRRSet(args.Zone, true)

	for _, v := range rrSet {
		rrSig := CreateNewRRSIG(args.Zone,
			args.ZSK,
			args.SignExpDate,
			v[0].Header().Ttl)
		err = rrSig.Sign(zskSigner, v)
		if err != nil {
			err = fmt.Errorf("cannot sign RRSig: %s", err)
			return nil, err
		}
		err = rrSig.Verify(args.ZSK, v)
		if err != nil {
			err = fmt.Errorf("cannot check RRSig: %s", err)
			return nil, err
		}
		args.RRs = append(args.RRs, rrSig)
	}

	rrDNSKeys := RRArray{args.ZSK, args.KSK}

	rrDNSKeySig := CreateNewRRSIG(args.Zone,
		args.KSK,
		args.SignExpDate,
		args.KSK.Hdr.Ttl)
	err = rrDNSKeySig.Sign(kskSigner, rrDNSKeys)
	if err != nil {
		return nil, err
	}
	err = rrDNSKeySig.Verify(args.KSK, rrDNSKeys)
	if err != nil {
		err = fmt.Errorf("cannot check ksk RRSig: %s", err)
		return nil, err
	}

	args.RRs = append(args.RRs, args.ZSK, args.KSK, rrDNSKeySig)

	sort.Sort(args.RRs)
	ds = args.KSK.ToDS(1)
	session.Log.Printf("DS: %s\n", ds) // SHA256
	err = args.RRs.WriteZone(args.Output)
	return ds, err
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
