package tools

/* leer la zona
   agregar DigestEnabled con 00s de digest
   ordenar zona
   firmar zona
   update DigestEnabled
   recalcular RRSIG de DigestEnabled y actualizar (o agregar?)
   recalcular DS?
   ojo que SOA y DigestEnabled deben ser el mismo en la zona a publicar */

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"sort"
	"strings"
)

// VerifyDigest validates a version of a zone with a valid ZONEMD RR.
func (ctx *Context) VerifyDigest() error {
	if ctx.File == nil {
		return fmt.Errorf("zone file not defined")
	}
	if ctx.Log == nil {
		return fmt.Errorf("log not defined")
	}

	if err := ctx.ReadAndParseZone(false); err != nil {
		return err
	}
	if ctx.zonemd == nil {
		return fmt.Errorf("cannot verify (ZONEMD RR not present)")
	}
	if ctx.soa.Serial != ctx.zonemd.Serial {
		return fmt.Errorf("ZONEMD serial does not match with SOA serial")
	}
	sort.Sort(ctx.rrs)
	if err := ctx.ValidateOrderedZoneDigest(); err != nil {
		return err
	}
	return nil
}

// Digest creates a version of a zone with a valid ZONEMD RR.
func (ctx *Context) Digest() error {
	if ctx.File == nil {
		return fmt.Errorf("zone file not defined")
	}
	if ctx.Output == nil {
		return fmt.Errorf("output not defined")
	}
	if ctx.Log == nil {
		return fmt.Errorf("log not defined")
	}

	if err := ctx.ReadAndParseZone(false); err != nil {
		return err
	}
	ctx.AddZONEMDRecord() // If it doesn't exist, adds a ZONEMD record.

	sort.Sort(ctx.rrs)

	if err := ctx.UpdateDigest(); err != nil {
		return err
	}
	// Write digest to out
	if err := ctx.WriteZone(); err != nil {
		return err
	}
	return nil
}

// AddZONEMDRecord adds a zone digest following draft-ietf-dnsop-dns-zone-digest-05
// we need the SOA info for that
func (ctx *Context) AddZONEMDRecord() {
	if ctx.zonemd == nil {
		zonemd := &dns.ZONEMD{
			Hdr: dns.RR_Header{
				Name:   ctx.soa.Header().Name,
				Rrtype: dns.TypeZONEMD,
				Class:  dns.ClassINET,
				Ttl:    ctx.soa.Header().Ttl,
			},
			Serial: ctx.soa.Serial,
			Scheme: 1, // SIMPLE
			Hash:   1, // SHA384
			Digest: strings.Repeat("0", 48*2),
		}
		ctx.rrs = append(ctx.rrs, zonemd)
		ctx.zonemd = zonemd
	}
}

// CleanDigests sets all root zone digests to 0
// It is used before zone signing
func (ctx *Context) CleanDigests() {
	for _, rr := range ctx.rrs {
		switch x := rr.(type) {
		case *dns.ZONEMD:
			x.Digest = strings.Repeat("0", len(x.Digest))
		}
	}
	return
}

// CalculateDigest calculates the digest for a PREVIOUSLY ORDERED zone.
// This method returns the digest hex value.
func (ctx *Context) CalculateDigest() (string, error) {
	if ctx.zonemd == nil {
		return "", fmt.Errorf("error trying to calculate a digest without a ZONEMD RR present")
	}
	h := sha512.New384()
	var prevRR dns.RR
	for _, rr := range ctx.rrs {
		switch {
		// Ignore ZONEMD RRs (new in v06)
		case rr.Header().Rrtype == dns.TypeZONEMD && rr.Header().Name == ctx.Config.Zone:
			continue
		// Ignore duplicate RRs
		case prevRR != nil && dns.IsDuplicate(prevRR, rr):
			continue
			// 3.4 Inclusions/Exclusions
			// The RRSIG covering ZONEMD MUST NOT be included because the RRSIG
			// will be updated after all digests have been calculated.
		case rr.Header().Rrtype == dns.TypeRRSIG &&
			rr.(*dns.RRSIG).TypeCovered == dns.TypeZONEMD:
			continue
		}
		buf := make([]byte, dns.MaxMsgSize)
		size, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			return "", err
		}
		h.Write(buf[:size])
		fmt.Printf("%s\n", rr)
		prevRR = rr
	}
	digest := hex.EncodeToString(h.Sum(nil))
	return digest, nil
}

// UpdateDigest calculates the digest for a PREVIOUSLY ORDERED zone with one ZONEMD RR
// This method updates the ZONEMD RR directly
func (ctx *Context) UpdateDigest() (err error) {
	digest, err := ctx.CalculateDigest()
	if err != nil {
		return
	}
	ctx.zonemd.Digest = digest
	return
}

// ValidateOrderedZoneDigest validates the digest for a PREVIOUSLY ORDERED zone.
// Returns nil if the calculated digest is equals the ZONEMD one, and an error otherwise.
// Follows the validation from https://datatracker.ietf.org/doc/draft-ietf-dnsop-dns-zone-digest.
// It is hardcoded to use SHA384 and SIMPLE scheme.
func (ctx *Context) ValidateOrderedZoneDigest() error {
	digest, err := ctx.CalculateDigest()
	if err != nil {
		return err
	}
	if strings.ToLower(digest) != strings.ToLower(ctx.zonemd.Digest) {
		return fmt.Errorf("invalid digest (expected: %s obtained: %s)", ctx.zonemd.Digest, digest)
	}
	return nil
}
