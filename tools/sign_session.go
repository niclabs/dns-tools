package tools

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"sort"
)

// ErrNoValidKeys represents an error returned when the session does not have valid keys
var ErrNoValidKeys = fmt.Errorf("no valid keys")

// SignSession represents an abstract signing session
type SignSession interface {
	Context() *Context
	GetKeys() (*SigKeys, error)
	GetPublicKeyBytes(*SigKeys) (zskBytes, kskBytes []byte, err error)
	DestroyAllKeys() error
	End() error
}

// SigKeys contains the four keys used in zone signing.
type SigKeys struct {
	zskSigner crypto.Signer
	kskSigner crypto.Signer
}

// Sign signs a zone file and outputs the result into out path (if its length is more than zero).
// It also dumps the new signed file zone to the standard output.
func Sign(session SignSession) (ds *dns.DS, err error) {
	ctx := session.Context()
	if ctx.Output == nil {
		return nil, fmt.Errorf("no output defined on context")
	}
	err = ctx.ReadAndParseZone(true)
	if err != nil {
		return
	}

	// Do we use DigestEnabled?
	if ctx.Config.DigestEnabled {
		ctx.AddZONEMDRecord()
		ctx.CleanDigests()
	}

	if ctx.Config.Info {
		ctx.rrs = append(ctx.rrs, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "_dnstools." + ctx.Config.Zone,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ctx.soa.Minttl,
			},
			Txt: []string{ctx.genInfo(session)},
		})
	}

	sort.Sort(ctx.rrs)

	ctx.AddNSEC13()
	keys, err := session.GetKeys()
	if err != nil {
		return nil, err
	}
	ctx.Log.Printf("Start signing...\n")
	rrSet := ctx.getRRSetList(true)

	// ok, we create DNSKEYS
	zsk, ksk, err := GetDNSKEY(keys, session)
	if err != nil {
		return nil, err
	}

	for _, v := range rrSet {
		if v[0].Header().Rrtype == dns.TypeZONEMD {
			continue // Skip it, we sign it post digest
		}
		rrSig := CreateNewRRSIG(ctx.Config.Zone,
			zsk,
			ctx.SignExpDate,
			v[0].Header().Ttl)
		err = rrSig.Sign(keys.zskSigner, v)
		if err != nil {
			err = fmt.Errorf("cannot sign RRSig: %s", err)
			return nil, err
		}
		err = rrSig.Verify(zsk, v)
		if err != nil {
			err = fmt.Errorf("cannot check RRSig: %s", err)
			return
		}
		ctx.rrs = append(ctx.rrs, rrSig)
	}

	rrDNSKeys := RRArray{zsk, ksk}

	rrDNSKeySig := CreateNewRRSIG(ctx.Config.Zone,
		ksk,
		ctx.SignExpDate,
		ksk.Hdr.Ttl)
	err = rrDNSKeySig.Sign(keys.kskSigner, rrDNSKeys)
	if err != nil {
		return nil, err
	}
	err = rrDNSKeySig.Verify(ksk, rrDNSKeys)
	if err != nil {
		err = fmt.Errorf("cannot check ksk RRSig: %s", err)
		return nil, err
	}

	ctx.rrs = append(ctx.rrs, zsk, ksk, rrDNSKeySig)

	// Sorting again
	sort.Sort(ctx.rrs)

	/* begin DigestEnabled digest updating (and signing)*/
	if ctx.Config.DigestEnabled {
		if ctx.UpdateDigest() != nil {
			return nil, fmt.Errorf("Error updating digest for DigestEnabled")
		}
		rrSig := CreateNewRRSIG(ctx.Config.Zone, zsk, ctx.SignExpDate,
			ctx.zonemd.Header().Ttl)
		err = rrSig.Sign(keys.zskSigner, []dns.RR{ctx.zonemd})
		if err != nil {
			err = fmt.Errorf("cannot sign RRSig: %s", err)
			return nil, err
		}
		err = rrSig.Verify(zsk, []dns.RR{ctx.zonemd})
		if err != nil {
			err = fmt.Errorf("cannot check RRSig: %s", err)
			return nil, err
		}
		ctx.rrs = append(ctx.rrs, rrSig)
		// Sort again
		sort.Sort(ctx.rrs)
	}
	/* end DigestEnabled digest updating*/

	ds = ksk.ToDS(1)
	ctx.Log.Printf("DS: %s\n", ds) // SHA256
	err = ctx.WriteZone()
	return ds, err
}

// GetDNSKEY returns two DNSKEY RRs based on the session SigKeys
func GetDNSKEY(keys *SigKeys, session SignSession) (zsk, ksk *dns.DNSKEY, err error) {
	zskBytes, kskBytes, err := session.GetPublicKeyBytes(keys)
	if err != nil {
		return
	}
	ctx := session.Context()
	zsk = CreateNewDNSKEY(
		ctx.Config.Zone,
		256,
		uint8(ctx.SignAlgorithm), // (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		ctx.soa.Minttl,
		base64.StdEncoding.EncodeToString(zskBytes),
	)
	if err != nil {
		return
	}
	ksk = CreateNewDNSKEY(
		ctx.Config.Zone,
		257,
		uint8(ctx.SignAlgorithm), // (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		ctx.soa.Minttl,           // SOA -> minimum TTL
		base64.StdEncoding.EncodeToString(kskBytes),
	)
	return
}
