package signer

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
	"time"
)

// RRSigTuple combines an RRSIg and the set related to it.
type RRSigTuple struct {
	RRSig *dns.RRSIG
	RRSet RRArray
}

// VerifyFile verifies the signatures in an already signed zone file.
func VerifyFile(filepath string) error {
	rrZone, _, err := readAndParseZone(filepath, false)
	if err != nil {
		return err
	}

	rrSets := rrZone.CreateRRSet(true)

	rrSigTuples := make(map[string]*RRSigTuple)

	var pzsk, pksk *dns.DNSKEY

	// Pairing each RRSet with its RRSig
	for _, set := range rrSets {
		if len(set) > 0 {
			if set[0].Header().Rrtype == dns.TypeDNSKEY {
				key1 := set[0].(*dns.DNSKEY)
				key2 := set[1].(*dns.DNSKEY)
				if key1.Flags == 256 {
					pzsk = key1
					pksk = key2
				} else if key1.Flags == 257 {
					pksk = key2
					pzsk = key1
				}
			}
			firstRR := set[0]
			var setHash string
			if firstRR.Header().Rrtype == dns.TypeRRSIG {
				for _, preSig := range set {
					sig := preSig.(*dns.RRSIG)
					setHash = fmt.Sprintf("%s#%s#%s", sig.Header().Name, dns.Class(sig.Header().Class), dns.Type(sig.TypeCovered))
					tuple, ok := rrSigTuples[setHash]
					if !ok {
						tuple = &RRSigTuple{}
						rrSigTuples[setHash] = tuple
					}
					tuple.RRSig = sig
				}
			} else {
				setHash = fmt.Sprintf("%s#%s#%s", firstRR.Header().Name, dns.Class(firstRR.Header().Class), dns.Type(firstRR.Header().Rrtype))
				tuple, ok := rrSigTuples[setHash]
				if !ok {
					tuple = &RRSigTuple{}
					rrSigTuples[setHash] = tuple
				}
				tuple.RRSet = set
			}
		}
	}

	if pzsk == nil || pksk == nil {
		return fmt.Errorf("couldn't find dnskeys")
	}

	// Checking each RRset RRSignature.
	for setName, tuple := range rrSigTuples {
		sig := tuple.RRSig
		set := tuple.RRSet
		if sig == nil {
			return fmt.Errorf("the set %s doesnt have a signature", setName)
		}
		if set == nil {
			return fmt.Errorf("the sig %s doesnt have a set", setName)
		}
		expDate := time.Unix(int64(sig.Expiration), 0)
		if expDate.Before(time.Now()) {
			_, _ = fmt.Fprintf(os.Stderr, "the sig %s is already expired. Exp date: %s", expDate.Format("2006-01-02 15:04:05"))
		}
		if set[0].Header().Rrtype == dns.TypeDNSKEY {
			// use pksk to verify
			if err := sig.Verify(pksk, set); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "on set %s, error: %s\n", setName, err)
			} else {
				_, _ = fmt.Fprintf(os.Stderr, "%s is ok\n", setName)
			}
		} else {
			// use pzsk to verify
			if err := sig.Verify(pzsk, set); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "on set %s, error: %s\n", setName, err)
			} else {
				_, _ = fmt.Fprintf(os.Stderr, "%s is ok\n", setName)
			}
		}
	}
	return nil
}
