package signer

import (
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log"
	"time"
)

// RRSigTuple combines an RRSIg and the set related to it.
type RRSigTuple struct {
	RRSig *dns.RRSIG
	RRSet RRArray
}

// VerifyFile verifies the signatures in an already signed zone file.
func VerifyFile(reader io.Reader, logger *log.Logger) (err error) {
	rrZone, _, err := readAndParseZone(reader, false)
	if err != nil {
		return
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
					pzsk = key2
					pksk = key1
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
		err = fmt.Errorf("couldn't find dnskeys")
		return err
	}

	// Checking each RRset RRSignature.
	for setName, tuple := range rrSigTuples {
		sig := tuple.RRSig
		set := tuple.RRSet
		if len(set) == 0 {
			err = fmt.Errorf("the RRSet %s has no elements", setName)
			return
		}
		if sig == nil {
			err = fmt.Errorf("the RRSet %s does not have a Signature", setName)
		}
		if set == nil {
			err = fmt.Errorf("the Signature %s does not have a RRSet", setName)
		}
		expDate := time.Unix(int64(sig.Expiration), 0)
		if expDate.Before(time.Now()) {
			err = fmt.Errorf(
				"the Signature for RRSet %s has already expired. Expiration date: %s",
				setName,
				expDate.Format("2006-01-02 15:04:05"),
			)
			logger.Printf("%s\n", err)
			return
		}
		if set[0].Header().Rrtype == dns.TypeDNSKEY {
			err = sig.Verify(pksk, set)
		} else {
			err = sig.Verify(pzsk, set)
		}
		if err != nil {
			logger.Printf("[Error] (%s) %s  \n", err, setName)
		} else {
			logger.Printf("[ OK  ] %s\n", setName)
		}
	}
	return
}
