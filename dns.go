package main

import (
  "fmt"
  "io/ioutil"
  . "github.com/miekg/dns"
  "strings"
  "sort"
  "time"
  "os"
)

/* begin []RR sorting */
type rrArray []RR
func (a rrArray) Len() int { return len(a) }
func (a rrArray) Swap(i,j int) { a[i],a[j] = a[j],a[i] }
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
  if (a[i].Header().Class == a[j].Header().Class) {
    return a[i].Header().Rrtype < a[j].Header().Rrtype
  } else {
    return a[i].Header().Class < a[j].Header().Class
  }
}
/* end RR sorting */

/* begin [][]RR sorting */
type rrSet [][]RR
func (a rrSet) Len() int { return len(a) }
func (a rrSet) Swap(i,j int) { a[i],a[j] = a[j],a[i] }
func (a rrSet) Less(i,j int) bool { 
  set := []RR{a[i][0],a[j][0]}
  return rrArray(set).Less(0,1)
}
/* end [][]RR sorting */

/* begin []uint16 sorting */
type ui16Array []uint16
func (a ui16Array) Len() int { return len(a) }
func (a ui16Array) Swap(i,j int) { a[i],a[j] = a[j],a[i] }
func (a ui16Array) Less(i,j int) bool { return a[i] < a[j] }
/* end uint16 sorting */

func ReadAndParseZone(filezone string) ([][]RR, uint32) {

  b, err := ioutil.ReadFile(filezone)
  if err != nil {
    panic ("Error, reading zone file")
    }

  minTTL := uint32(3600)

  zone := string(b)
  rrs := []RR{}

  z:= NewZoneParser(strings.NewReader(zone), "", "")
  if err := z.Err(); err != nil {
    fmt.Fprintf(os.Stderr,"Error parsing zone %s\n",err)
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

  // RRsets are RR grouped by label and class

  rr := rrs[0]
  set := make([][]RR,0,32)
  set = append(set,make([]RR,0,32))
  set[0] = append(set[0],rr)
  i := 0
  for k := 1; k < len(rrs); k++ {
    h0 := rr.Header()
    h1 := rrs[k].Header()
    if !(h0.Class == h1.Class && strings.ToLower(h0.Name) ==  strings.ToLower(h1.Name)) {
      i = i + 1
      rr = rrs[k]
      set = append(set,make([]RR,0,32))
    }
    set[i] = append(set[i],rrs[k])
  }
  return set, uint32(minTTL)
}

func CreateNewDNSKEY(zone string, f uint16, a uint8, ttl uint32, k string) *DNSKEY {

  key := &DNSKEY { Flags: f, Protocol: 3, Algorithm: a }
  key.Hdr = RR_Header { Name: zone, Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: ttl }
  key.PublicKey = k

  return key
}


func CreateNewRRSIG(zone string, key RR) *RRSIG {

  k := key.(*DNSKEY)

  rrsig := &RRSIG { Algorithm : k.Algorithm}
  rrsig.Hdr.Ttl = k.Hdr.Ttl
  rrsig.SignerName = strings.ToLower(zone)
  rrsig.KeyTag = k.KeyTag()
  rrsig.Inception = uint32(time.Now().Unix())
  rrsig.Expiration = rrsig.Inception + (60*60*24*365)  // change to key exp

  return rrsig
}

func PrintZone(r [][]RR) {

  for _, rrs := range r {
    for _, rr := range rrs {
      fmt.Println(rr)
    }
  }
}

func AddNSECRecords(set [][]RR) {

  n := len(set)
  for i , rrs := range(set) {
    typemap := make(map[uint16]bool)
    typearray := make([]uint16,0)
    for _, rr := range rrs {
      typemap[rr.Header().Rrtype] = true
    }
    typemap[TypeNSEC] = true

    for k,_ := range typemap {
      typearray = append (typearray,k)
    }

    sort.Sort(ui16Array(typearray))

    nsec := &NSEC { }
    nsec.Hdr.Name = rrs[0].Header().Name
    nsec.Hdr.Rrtype = TypeNSEC
    nsec.Hdr.Class = ClassINET
    nsec.Hdr.Ttl = rrs[0].Header().Ttl
    nsec.NextDomain = set[(i+1) % n][0].Header().Name
    nsec.TypeBitMap = typearray
    
    set[i] = append(set[i],nsec)
    sort.Sort(rrArray(set[i]))
  }

  sort.Sort(rrSet(set))
}

