package signer

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
	"os"
	"sort"

	"time"
)

// FileSession represents a sessionType-based session. It includes the context, the session handle and a Label String,
// used in creation and retrieval of DNS keys.
type FileSession struct {
	*Context                           // HSM Tools Context
	File          *os.File             // PKCS#11 Context
	SignAlgorithm SignAlgorithm
}

// PKCS11Sign signs a zone file and outputs the result into out path (if its length is more than zero).
// It also dumps the new signed filezone to the standard output.
func (session *FileSession) Sign() (ds *dns.DS, err error) {
	if session.Output == nil {
		return nil, fmt.Errorf("no output defined on context")
	}

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
func (session *FileSession) End() error {
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
