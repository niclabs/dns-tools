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
	RRSig   *dns.RRSIG
	RRArray RRArray
}

// VerifyFile verifies the signatures in an already signed zone file.
// zone represents the domain origin, while filepath is the zone location, and it is used
// to resolve $INCLUDE directives. reader has the zone input and logger allows us to log the operations.
func VerifyFile(origin, path string, reader io.Reader, logger *log.Logger) (err error) {
	ctx := &Context{
		ContextConfig: &ContextConfig{
			Zone: origin,
			FilePath: path,
		},
		File: reader,
		Log: logger,
	}

	if err = ctx.ReadAndParseZone(false); err != nil {
		return
	}
	rrSet := ctx.rrs.createRRSet(origin, true)
	nsNames := getAllNSNames(ctx.rrs)

	rrSigTuples := make(map[string]*RRSigTuple)

	var pzsk, pksk *dns.DNSKEY

	// Pairing each RRArray with its RRSig
	for _, rrArray := range rrSet {
		if len(rrArray) > 0 && rrArray.isSignable(origin, nsNames) {
			if rrArray[0].Header().Rrtype == dns.TypeDNSKEY {
				key1 := rrArray[0].(*dns.DNSKEY)
				key2 := rrArray[1].(*dns.DNSKEY)
				if key1.Flags == 256 {
					pzsk = key1
					pksk = key2
				} else if key1.Flags == 257 {
					pzsk = key2
					pksk = key1
				}
			}
			firstRR := rrArray[0]
			var setHash string
			if firstRR.Header().Rrtype == dns.TypeRRSIG {
				for _, preSig := range rrArray {
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
				tuple.RRArray = rrArray
			}
		}
	}

	if pzsk == nil || pksk == nil {
		err = fmt.Errorf("couldn't find dnskeys")
		return err
	}

	// Checking each RRset RRSignature.
	ctx.Log.Printf("number of signatures: %d\n", len(rrSigTuples))
	for setName, tuple := range rrSigTuples {
		sig := tuple.RRSig
		arr := tuple.RRArray
		if len(arr) == 0 {
			err = fmt.Errorf("the RRArray %s has no elements", setName)
			return
		}
		if sig == nil {
			err = fmt.Errorf("the RRArray %s does not have a Signature", setName)
			return
		}
		expDate := time.Unix(int64(sig.Expiration), 0)
		if expDate.Before(time.Now()) {
			err = fmt.Errorf(
				"the Signature for RRArray %s has already expired. Expiration date: %s",
				setName,
				expDate.Format("2006-01-02 15:04:05"),
			)
			ctx.Log.Printf("%s\n", err)
			return
		}
		if arr[0].Header().Rrtype == dns.TypeDNSKEY {
			err = sig.Verify(pksk, arr)
		} else {
			err = sig.Verify(pzsk, arr)
		}
		if err != nil {
			ctx.Log.Printf("[Error] (%s) %s  \n", err, setName)
		} else {
			ctx.Log.Printf("[ OK  ] %s\n", setName)
		}
	}
	return
}
