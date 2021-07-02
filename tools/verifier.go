package tools

import (
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

// RRSigPair combines an RRSIg and the set related to it.
type RRSigPair struct {
	RRSig *dns.RRSIG
	RRSet RRArray
}

var ErrNotEnoughDNSkeys = fmt.Errorf("could not find enough dnskeys")

// VerifyFile verifies the signatures in an already signed zone file.
// zone represents the domain origin, while path is the zone location, and it is used
// to resolve $INCLUDE directives. reader has the zone input and logger allows us to log the operations.
func (ctx *Context) VerifyFile() (err error) {
	ctx.Log.Printf("Zone must be valid before %s to succeed", ctx.Config.VerifyThreshold.String())
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

	rrSigPairs := make(map[string]*RRSigPair)

	// Pairing each RRArray with its RRSig
	for _, set := range setList {
		if len(set) > 0 && ctx.isSignable(set[0].Header().Name) {
			firstRR := set[0]
			var setHash string
			if firstRR.Header().Rrtype == dns.TypeRRSIG {
				for _, sig := range set {
					setHash = getRRSIGHash(sig.(*dns.RRSIG))
					pair, ok := rrSigPairs[setHash]
					if !ok {
						pair = &RRSigPair{}
						rrSigPairs[setHash] = pair
					}
					pair.RRSig = sig.(*dns.RRSIG)
				}
			} else {
				setHash = getHash(firstRR, true)
				pair, ok := rrSigPairs[setHash]
				if !ok {
					pair = &RRSigPair{}
					rrSigPairs[setHash] = pair
				}
				pair.RRSet = set
			}
		}
	}

	if len(ctx.DNSKEYS.ZSK) == 0 || len(ctx.DNSKEYS.KSK) == 0 {
		err = ErrNotEnoughDNSkeys
		return err
	}

	rrSignatures := make(map[string]*RRSigPair)

	for setName, pair := range rrSigPairs {
		if pair.RRSet == nil || len(pair.RRSet) == 0 || pair.RRSig == nil {
			// err = fmt.Errorf("the RRSet %s has no elements", setName)
			continue
		}
		rrSignatures[setName] = pair
	}

	// Checking each RRset RRSignature.
	ctx.Log.Printf("number of signatures: %d", len(rrSignatures))
	for setName, pair := range rrSignatures {
		sig := pair.RRSig
		set := pair.RRSet
		expDate := time.Unix(int64(sig.Expiration), 0)
		if expDate.Before(ctx.Config.VerifyThreshold) {
			err = fmt.Errorf(
				"the Signature for RRSet %s has already expired. Expiration date: %s",
				setName,
				expDate.Format("2006-01-02 15:04:05"),
			)
			return
		}
		var key *dns.DNSKEY
		var ok bool
		if set[0].Header().Rrtype == dns.TypeDNSKEY {
			key, ok = ctx.DNSKEYS.KSK[sig.KeyTag]
			if !ok {
				key, ok = ctx.DNSKEYS.ZSK[sig.KeyTag]
			}
		} else {
			key, ok = ctx.DNSKEYS.ZSK[sig.KeyTag]
		}
		if !ok {
			err = fmt.Errorf("key with keytag declared in signature (%d) not found (keys available: ksk=[%v] zsk=[%v])", sig.KeyTag, ctx.DNSKEYS.KSK, ctx.DNSKEYS.ZSK)
			ctx.Log.Print(err.Error())
			return
		}
		if key.Algorithm != sig.Algorithm {
			err = fmt.Errorf("key and signature algorithm does not match")
			return
		}
		err = sig.Verify(key, set)
		if err != nil {
			ctx.Log.Printf("[Error] (%s) %s", err, setName)
			return
		} else {
			ctx.Log.Printf("[ OK  ] %s", setName)
		}
	}
	ctx.PrintDS()
	return
}
