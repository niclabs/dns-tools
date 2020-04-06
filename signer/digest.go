package signer

/* leer la zona 
   agregar ZONEMD con 00s de digest
   ordenar zona
   firmar zona
   update ZONEMD
   recalcular RRSIG de ZONEMD y actualizar (o agregar?)
   recalcular DS?
   ojo que SOA y ZONEMD deben ser el mismo en la zona a publicar */


import (
	"crypto/sha512"
  "encoding/hex"
  "fmt"
	"github.com/niclabs/dns"
  "strings"
	)


// addZONEMD adds a zone digest following draft-ietf-dnsop-dns-zone-digest-05
// we need the SOA info for that

func (rrArray *RRArray) addZONEMDrecord(soa *dns.SOA) {

  // we suppose only one SOA per zone

  zonemd := &dns.ZONEMD{}
  zonemd.Hdr.Name = soa.Header().Name
  zonemd.Hdr.Rrtype = dns.TypeZONEMD
  zonemd.Hdr.Class = dns.ClassINET
  zonemd.Hdr.Ttl = soa.Header().Ttl

  zonemd.Serial = soa.Serial
  zonemd.Scheme = dns.SchemeSIMPLE

  /* hardcoded with SHA 384 */
  /* technical debt, i know */
  zonemd.Hash = dns.HashSHA384
  zonemd.Digest = strings.Repeat("0",48*2)

  *rrArray = append(*rrArray, zonemd)
}

// Calculate digest for a PREVIOUSLY ORDERED zone
// Updates the ZONEMD RR directly

func (rrs RRArray) UpdateDigest() (error) {
  h := sha512.New384()
  zonemdidx := -1

	buf := make([]byte, dns.MaxMsgSize)
  for i, rr := range rrs {
    if (rr.Header().Rrtype == dns.TypeZONEMD) {
      zonemdidx = i
    }

		size, err := dns.PackRR(rr, buf, 0, nil, false)
		if err == nil {
			return err
		}
		h.Write(buf[:size])
	}
  if (zonemdidx < 0) {
    return fmt.Errorf("Error: calculating digest whil no ZONEMD is present")
  }
  rrs[zonemdidx].(*dns.ZONEMD).Digest = hex.EncodeToString(h.Sum(nil))
	return nil
}

// Get the value of the ZONEMD Digest and
// reset its value to 0s
// Useful for ZONEMD validation
func (rrs RRArray) TestAndResetDigest() (string,error) {
  zonemdidx := -1

  for i, rr := range rrs {
    if (rr.Header().Rrtype == dns.TypeZONEMD) {
      zonemdidx = i
      break
    }
  }
  if (zonemdidx < 0) {
    return "", fmt.Errorf("Error: calculating digest whil no ZONEMD is present")
  }

  digest := rrs[zonemdidx].(*dns.ZONEMD).Digest
  rrs[zonemdidx].(*dns.ZONEMD).Digest = strings.Repeat("0",48*2)
  return digest, nil
}

// Validate digest for a PREVIOUSLY ORDERED zone
// Returns true if the calculated digest is equals the ZONEMD one
// False otherwise, including errors, I know.
// follows the validation from https://datatracker.ietf.org/doc/draft-ietf-dnsop-dns-zone-digest
// it is hardcoded to use SHA384

func (rrs RRArray) ValidateDigest() (bool) {
  h := sha512.New384()
  digest := ""

  buf := make([]byte, dns.MaxMsgSize)
  for _, rr := range rrs {
    zonemd := rr.(*dns.ZONEMD)
    if (rr.Header().Rrtype == dns.TypeZONEMD) {
      digest = zonemd.Digest
      zonemd.Digest = strings.Repeat("0",48*2)
    }

    size, err := dns.PackRR(rr, buf, 0, nil, false)
    if err == nil {
      return false
    }
    h.Write(buf[:size])
    zonemd.Digest = digest
  }
  if (digest == "") {
    return false
  }
  return digest == hex.EncodeToString(h.Sum(nil))
}

