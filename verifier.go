package main

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
)

type RRSigTuple struct {
	RRSig *dns.RRSIG
	RRSet rrArray
}

func VerifyFile(filepath string) error {
	rrZone, _ := ReadAndParseZone(filepath)

	rrSets := CreateRRset(rrZone, true)

	rrSigtuples := make(map[string]*RRSigTuple)

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
			rep := set[0]
			var setHashString string
			if set[0].Header().Rrtype == dns.TypeRRSIG {
				for _, presig := range set {
					sig := presig.(*dns.RRSIG)
					setHashString = fmt.Sprintf("%s#%s#%s", sig.Header().Name, dns.Class(sig.Header().Class), dns.Type(sig.TypeCovered))
					tuple, ok := rrSigtuples[setHashString]
					if !ok {
						tuple = &RRSigTuple{}
						rrSigtuples[setHashString] = tuple
					}
					tuple.RRSig = sig
				}
			} else {
				setHashString = fmt.Sprintf("%s#%s#%s", rep.Header().Name, dns.Class(rep.Header().Class), dns.Type(rep.Header().Rrtype))
				tuple, ok := rrSigtuples[setHashString]
				if !ok {
					tuple = &RRSigTuple{}
					rrSigtuples[setHashString] = tuple
				}
				tuple.RRSet = set
			}

		}
	}

	if pzsk == nil || pksk == nil {
		return fmt.Errorf("couldn't find dnskeys")
	}

	// Checking each RRset RRSignature.

	for setName, tuple := range rrSigtuples {
		sig := tuple.RRSig
		set := tuple.RRSet
		if sig == nil {
			return fmt.Errorf("the set %s doesnt have a signature", setName)
		}
		if set == nil {
			return fmt.Errorf("the sig %s doesnt have a set", setName)
		}

		if set[0].Header().Rrtype == dns.TypeDNSKEY {
			// use pksk to verify
			if err := sig.Verify(pksk, set); err != nil {
				fmt.Fprintf(os.Stderr, "on set %s, error: %s\n", setName, err)
			} else {
				fmt.Fprintf(os.Stderr, "%s is ok\n", setName)
			}
		} else {
			// use pzsk to verify
			if err := sig.Verify(pzsk, set); err != nil {
				fmt.Fprintf(os.Stderr, "on set %s, error: %s\n", setName, err)
			} else {
				fmt.Fprintf(os.Stderr, "%s is ok\n", setName)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "done")
	return nil
}
