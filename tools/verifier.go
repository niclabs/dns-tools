package tools

import (
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

// RRSigTuple combines an RRSIg and the set related to it.
type RRSigTuple struct {
	RRSig   *dns.RRSIG
	RRArray RRArray
}

// VerifyFile verifies the signatures in an already signed zone file.
// zone represents the domain origin, while path is the zone location, and it is used
// to resolve $INCLUDE directives. reader has the zone input and logger allows us to log the operations.
func (ctx *Context) VerifyFile() (err error) {
	if ctx.File == nil {
		return fmt.Errorf("zone file not defined")
	}
	if ctx.Output == nil {
		ctx.Output = os.Stdout // change it to error?
	}
	if ctx.Log == nil {
		return fmt.Errorf("log not defined")
	}
	if err = ctx.ReadAndParseZone(false); err != nil {
		return
	}
	setList := ctx.getRRSetList(true)

	rrSigTuples := make(map[string]*RRSigTuple)

	pzsk := make(map[uint16]*dns.DNSKEY, 0)
	pksk := make(map[uint16]*dns.DNSKEY, 0)

	// Pairing each RRArray with its RRSig
	for _, set := range setList {
		isSignable := true
		for _, rr := range set {
			if !ctx.isSignable(rr.Header().Name) {
				isSignable = false
				break
			}
		}
		if len(set) > 0 && isSignable {
			if set[0].Header().Rrtype == dns.TypeDNSKEY {
				for _, rr := range set {
					key := rr.(*dns.DNSKEY)
					switch key.Flags {
					case 256:
						pzsk[key.KeyTag()] = key
					case 257:
						ds := key.ToDS(1)
						ctx.Log.Printf("DS for KSK with tag %d is \"%s\"", key.KeyTag(), ds)
						pksk[key.KeyTag()] = key
					}
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
				tuple.RRArray = set
			}
		}
	}

	if len(pzsk) == 0 || len(pksk) == 0 {
		err = fmt.Errorf("could not find enough dnskeys")
		return err
	}

	// Checking each RRset RRSignature.
	ctx.Log.Printf("number of signatures: %d\n", len(rrSigTuples))
	for setName, tuple := range rrSigTuples {
		sig := tuple.RRSig
		set := tuple.RRArray
		if len(set) == 0 {
			err = fmt.Errorf("the RRSet %s has no elements", setName)
			continue
		}
		if sig == nil {
			err = fmt.Errorf("the RRSet %s does not have a Signature", setName)
			continue
		}
		expDate := time.Unix(int64(sig.Expiration), 0)
		if expDate.Before(ctx.Config.VerifyThreshold) {
			err = fmt.Errorf(
				"the Signature for RRSet %s has already expired. Expiration date: %s",
				setName,
				expDate.Format("2006-01-02 15:04:05"),
			)
			ctx.Log.Printf("%s\n", err)
			continue
		}
		var key *dns.DNSKEY
		var ok bool
		if set[0].Header().Rrtype == dns.TypeDNSKEY {
			key, ok = pksk[sig.KeyTag]
			if !ok {
				key, ok = pzsk[sig.KeyTag]
			}
		} else {
			key, ok = pzsk[sig.KeyTag]
		}
		if !ok {
			return fmt.Errorf("Key with keytag declared in signature not found")
		}
		if key.Algorithm != sig.Algorithm {
			return fmt.Errorf("Key and signature algorithm does not match")
		}
		err = sig.Verify(key, set)
		if err != nil {
			ctx.Log.Printf("[Error] (%s) %s  \n", err, setName)
		} else {
			ctx.Log.Printf("[ OK  ] %s\n", setName)
		}
	}
	return
}
