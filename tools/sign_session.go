package tools

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"
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
	ctx.Log.Printf("Starting signing process for %s", ctx.Config.Zone)

	if ctx.Config.Info {
		ctx.Log.Println("Adding _created_by TXT for marking library usage")
		ctx.rrs = append(ctx.rrs, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "_created_by." + ctx.Config.Zone,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ctx.soa.Minttl,
			},
			Txt: []string{ctx.genInfo(session)},
		})
	}
	ctx.Log.Println("Creating NSEC/NSEC3 RRs")
	ctx.AddNSEC13()
	keys, err := session.GetKeys()
	if err != nil {
		return nil, err
	}
	ctx.Log.Println("Signing")
	rrSet := ctx.getRRSetList(true)

	// ok, we create DNSKEYS
	zsk, ksk, err := GetDNSKEY(keys, session)
	if err != nil {
		return nil, err
	}
	numTries := 3
	for i, v := range rrSet {
		if v[0].Header().Rrtype == dns.TypeZONEMD {
			ctx.Log.Printf("[Signature %d/%d] Skipping RRSet because it is a ZONEMD RR", i+1, len(rrSet)+1)
			continue // Skip it, we sign it post digest
		}
		for try := 1; try <= numTries; try++ {
			rrSig := CreateNewRRSIG(ctx.Config.Zone,
				zsk,
				ctx.Config.RRSIGExpDate,
				v[0].Header().Ttl)
			ctx.Log.Printf("[Signature %d/%d] Creating RRSig for RRSet %s", i+1, len(rrSet)+1, v.String())
			err = rrSig.Sign(keys.zskSigner, v)
			if err != nil {
				err = fmt.Errorf("cannot create RRSig: %s", err)
				if try == numTries {
					return
				}
				ctx.Log.Printf("%s. Retrying", err)
				continue
			}
			ctx.Log.Printf("[Signature %d/%d] Verifying RRSig for RRSet %s", i+1, len(rrSet)+1, v.String())
			err = rrSig.Verify(zsk, v)
			if err != nil {
				err = fmt.Errorf("RRSig does not validate: %s", err)
				if try == numTries {
					return
				}
				ctx.Log.Printf("%s. Retrying", err)
				continue
			}
			ctx.rrs = append(ctx.rrs, rrSig)
			break
		}
	}

	rrDNSKeys := RRArray{zsk, ksk}

	rrDNSKeySig := CreateNewRRSIG(ctx.Config.Zone,
		ksk,
		ctx.Config.RRSIGExpDate,
		ksk.Hdr.Ttl)
	ctx.Log.Printf("[Signature %d/%d] Creating RRSig for DNSKEY", len(rrSet)+1, len(rrSet)+1)
	err = rrDNSKeySig.Sign(keys.kskSigner, rrDNSKeys)
	if err != nil {
		return nil, err
	}
	ctx.Log.Printf("[Signature %d/%d] Verifying RRSig for DNSKEY", len(rrSet)+1, len(rrSet)+1)
	err = rrDNSKeySig.Verify(ksk, rrDNSKeys)
	if err != nil {
		err = fmt.Errorf("cannot check ksk RRSig: %s", err)
		return nil, err
	}

	ctx.rrs = append(ctx.rrs, zsk, ksk, rrDNSKeySig)

	/* begin DigestEnabled digest updating (and signing)*/
	if ctx.Config.DigestEnabled {
		// Sorting
		ctx.Log.Printf("Sorting zone")
		quickSort(ctx.rrs)
		ctx.Log.Printf("Zone Sorted")
		ctx.Log.Printf("Updating zone digests")
		if err := ctx.UpdateDigest(); err != nil {
			return nil, fmt.Errorf("error updating ZONEMD Digest: %s", err)
		}

		rrSig := CreateNewRRSIG(
			ctx.Config.Zone,
			zsk,
			ctx.Config.RRSIGExpDate,
			ctx.zonemd[0].Header().Ttl,
		)

		var zmdrrs []dns.RR

		for _, zmd := range ctx.zonemd {
			zmdrrs = append(zmdrrs, dns.RR(zmd))
		}

		ctx.Log.Printf("Signing new zone digest")
		err = rrSig.Sign(keys.zskSigner, zmdrrs)
		if err != nil {
			err = fmt.Errorf("cannot create RRSig: %s", err)
			return nil, err
		}
		ctx.Log.Printf("Verifying new zone digest")
		err = rrSig.Verify(zsk, zmdrrs)
		if err != nil {
			err = fmt.Errorf("cannot check RRSig: %s", err)
			return nil, err
		}
		ctx.rrs = append(ctx.rrs, rrSig)
		ctx.Log.Printf("Digest calculation done")
	}
	/* end DigestEnabled digest updating*/
	ctx.Log.Printf("Signing done, writing zone")

	ds = ksk.ToDS(dns.SHA256)
	ctx.Log.Printf("DS: %s", ds) // SHA256
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
