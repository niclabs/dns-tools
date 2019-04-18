package main

import (
  "fmt"
  "io/ioutil"
  . "github.com/miekg/dns"
  "strings"
  "time"
)

func ReadAndParseZone(filezone string) (map[uint16][]RR, uint32) {
  
  b, err := ioutil.ReadFile(filezone)
  if err != nil {
    panic ("Error, reading zone file")
    }

  minTTL := uint32(3600)
 
  zone := string(b)
  rrs := map[uint16][]RR{}
  z:= NewZoneParser(strings.NewReader(zone), "", "")
  for rr, ok := z.Next(); ok; rr, ok = z.Next() {
    rrs[rr.Header().Rrtype] = append(rrs[rr.Header().Rrtype],rr)
    if (rr.Header().Rrtype == TypeSOA) { 
      var soa *SOA
      soa = rr.(*SOA)
      minTTL = soa.Minttl 
      }
    }

  if err := z.Err(); err != nil {
    fmt.Println("Error parsing zone",err)
    return nil,0
  }
  return rrs, uint32(minTTL)
}

func CreateNewDNSKEY(zone string, f uint16, a uint8, ttl uint32, k string) (uint16, RR) {

  key := &DNSKEY { Flags: f, Protocol: 3, Algorithm: a }
  key.Hdr = RR_Header { Name: zone, Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: ttl }
  key.PublicKey = k

  return TypeDNSKEY, key
}

func CreateNewRRSIG(zone string, t uint16, rrs []RR, key RR, sig string) RR {

  k := key.(*DNSKEY)

  rrsig := &RRSIG { Algorithm : k.Algorithm}
  rrsig.Hdr = RR_Header { Name: rrs[0].Header().Name, 
                          Rrtype: TypeRRSIG, 
                          Class: ClassINET}
  rrsig.Hdr.Ttl = k.Hdr.Ttl
  rrsig.TypeCovered = t
  rrsig.SignerName = zone
  rrsig.Labels = uint8(len(rrs))
  rrsig.Signature = sig
  rrsig.KeyTag = k.KeyTag()
  rrsig.OrigTtl = k.Hdr.Ttl
  rrsig.Inception = uint32(time.Now().Unix())
  rrsig.Expiration = rrsig.Inception + (60*60*24*365)  // change to key exp
  return rrsig
}

