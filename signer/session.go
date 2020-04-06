package signer

import (
	"github.com/niclabs/dns"
	"crypto"
	"encoding/base64"
	"fmt"
	"sort"
)

var NoValidKeys = fmt.Errorf("No valid keys")

type Session interface {
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
func Sign(session Session) (ds *dns.DS, err error) {
	ctx := session.Context()
	if ctx.Output == nil {
		return nil, fmt.Errorf("no output defined on context")
	}
  soa, err1 := ctx.ReadAndParseZone(true);
  if err1 != nil {
		return nil, err
	}

  // Do we use ZONEMD?
  if ctx.ZONEMD {
    ctx.rrs.addZONEMDrecord(soa)
  }

  sort.Sort(ctx.rrs)

	ctx.AddNSEC13()
	keys, err := session.GetKeys()
	if err != nil {
		return nil, err
	}
	ctx.Log.Printf("Start signing...\n")
	rrSet := ctx.rrs.createRRSet(ctx.Zone, true)

	// ok, we create DNSKEYS
	zsk, ksk, err := GetDNSKEY(keys, session)
	if err != nil {
		return nil, err
	}

	for _, v := range rrSet {
		rrSig := CreateNewRRSIG(ctx.Zone,
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

	rrDNSKeySig := CreateNewRRSIG(ctx.Zone,
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

	sort.Sort(ctx.rrs)
	ds = ksk.ToDS(1)
	ctx.Log.Printf("DS: %s\n", ds) // SHA256
	err = ctx.rrs.writeZone(ctx.Output)
	return ds, err
}

func GetDNSKEY(keys *SigKeys, session Session) (zsk, ksk *dns.DNSKEY, err error) {
	zskBytes, kskBytes, err := session.GetPublicKeyBytes(keys)
	if err != nil {
		return
	}
	ctx := session.Context()
	zsk = CreateNewDNSKEY(
		ctx.Zone,
		256,
		uint8(ctx.SignAlgorithm), // (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		ctx.MinTTL,
		base64.StdEncoding.EncodeToString(zskBytes),
	)
	if err != nil {
		return
	}
	ksk = CreateNewDNSKEY(
		ctx.Zone,
		257,
		uint8(ctx.SignAlgorithm), // (https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
		ctx.MinTTL,               // SOA -> minimum TTL
		base64.StdEncoding.EncodeToString(kskBytes),
	)
	return
}
