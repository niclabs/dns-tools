package main

import (
  "fmt"
  "io/ioutil"
  . "github.com/miekg/dns"
  "strings"
  "sort"
  "time"
)

type rrArray []RR

func (a rrArray) Len() int{

  return len(a)
}

func (a rrArray) Swap(i,j int) {

  a[i],a[j] = a[j],a[i]
}

func (a rrArray) Less(i,j int) bool {

  si := strings.Split(strings.ToLower(a[i].Header().Name),".")
  sj := strings.Split(strings.ToLower(a[j].Header().Name),".")

  if (len(si) < len (sj)  || len(si) > len (sj)) {
    return len(si) < len (sj)
  }

  // Equal lenght, check from left to right omiting .[nothing]

  for k:= len(si)-2; k >= 0; k-- {
    if (si[k] < sj[k]) { return true } else if (si[k] > sj[k]) { return false}
  }
  return a[i].Header().Rrtype < a[j].Header().Rrtype
}

func ReadAndParseZone(filezone string) ([]RR, uint32) {

  b, err := ioutil.ReadFile(filezone)
  if err != nil {
    panic ("Error, reading zone file")
    }

  minTTL := uint32(3600)

  zone := string(b)
  rrs := []RR{}

  z:= NewZoneParser(strings.NewReader(zone), "", "")
  if err := z.Err(); err != nil {
    fmt.Println("Error parsing zone",err)
    return nil,0
  }

  for rr, ok := z.Next(); ok; rr, ok = z.Next() {
    rrs = append(rrs,rr)
    if (rr.Header().Rrtype == TypeSOA) { 
      var soa *SOA
      soa = rr.(*SOA)
      minTTL = soa.Minttl 
      }
    }

  sort.Sort(rrArray(rrs))
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
  rrsig.SignerName = strings.ToLower(zone)
  rrsig.Labels = uint8(len(rrs))
  rrsig.Signature = sig
  rrsig.KeyTag = k.KeyTag()
  rrsig.OrigTtl = k.Hdr.Ttl
  rrsig.Inception = uint32(time.Now().Unix())
  rrsig.Expiration = rrsig.Inception + (60*60*24*365)  // change to key exp
  return rrsig
}

func PrintZone(r []RR) {

  for _, rr := range r {
    fmt.Println(rr)
  }
}

func AddNSECRecords(rrs []RR) []RR {

  typemap := make([]uint16,0)
  name := rrs[0].Header().Name
  typemap = append(typemap,rrs[0].Header().Rrtype)
  l := len(rrs)
  
  for i:=1; i < l; i++ {
    if rrs[i].Header().Name == name {
      typemap = append(typemap,rrs[i].Header().Rrtype)
    } else {
      typemap = append(typemap,TypeNSEC)
      nsec := &NSEC { }
      nsec.Hdr.Name = name
      nsec.Hdr.Rrtype = TypeNSEC
      nsec.Hdr.Class = ClassINET
      nsec.Hdr.Ttl = rrs[i-1].Header().Ttl
      nsec.NextDomain = rrs[i].Header().Name
      nsec.TypeBitMap = typemap
      rrs = append(rrs,nsec)
      // reset all
      typemap = make([]uint16,0)
      name = rrs[i].Header().Name
      typemap = append(typemap,rrs[i].Header().Rrtype)
    }
  }
  // last record
  typemap = append(typemap,TypeNSEC)
  nsec := &NSEC { }
  nsec.Hdr.Name = name
  nsec.Hdr.Rrtype = TypeNSEC
  nsec.Hdr.Class = ClassINET
  nsec.Hdr.Ttl = rrs[len(rrs)-1].Header().Ttl
  nsec.NextDomain = rrs[0].Header().Name
  nsec.TypeBitMap = typemap
  rrs = append(rrs,nsec)

  sort.Sort(rrArray(rrs))
  return rrs
}

// Code "borrowed" from https://github.com/miekg/dns/blob/master/dnssec.go

func (rr *RRSIG) BytesToSign(rrset []RR) []byte {
  if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
    return nil
    }

  h0 := rrset[0].Header()
	rr.Hdr.Rrtype = TypeRRSIG
	rr.Hdr.Name = h0.Name
	rr.Hdr.Class = h0.Class
	if rr.OrigTtl == 0 { // If set don't override
		rr.OrigTtl = h0.Ttl
	}
	rr.TypeCovered = h0.Rrtype
	rr.Labels = uint8(CountLabel(h0.Name))

	if strings.HasPrefix(h0.Name, "*") {
		rr.Labels-- // wildcard, remove from label count
	}

	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = rr.TypeCovered
	sigwire.Algorithm = rr.Algorithm
	sigwire.Labels = rr.Labels
	sigwire.OrigTtl = rr.OrigTtl
	sigwire.Expiration = rr.Expiration
	sigwire.Inception = rr.Inception
	sigwire.KeyTag = rr.KeyTag
	// For signing, lowercase this name
	sigwire.SignerName = strings.ToLower(rr.SignerName)

	// Create the desired binary blob
	signdata := make([]byte, DefaultMsgSize)
	n, err := packSigWire(sigwire, signdata)
	if err != nil {
		return err
	}
	signdata = signdata[:n]
	wire, err := rawSignatureData(rrset, rr)

        return append(signdata, wire...)
}


