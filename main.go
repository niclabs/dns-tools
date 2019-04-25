package main

import (
  "fmt"
  "encoding/gob"
  b64 "encoding/base64"
  "bytes"
  "sort"
)

// GetBytes direct from stackoverflow

func GetBytes(key interface{}) []byte {
  
  var buf bytes.Buffer
  enc := gob.NewEncoder(&buf)
  err := enc.Encode(key)
  if err != nil {
    return nil
  }
  return buf.Bytes()
}

func main() {

  p, session, zone, zfile, reset_keys := init_dHSMsigner()
  defer p.Destroy()
  defer p.Finalize()
  defer p.CloseSession(session)
  defer p.Logout(session)

  if zone[len(zone)-1] != '.' { zone = zone + "."}

  fmt.Println("Signing...",zfile,"for",zone,"with reset keys =",reset_keys)

  rrset, minTTL := ReadAndParseZone(zfile)

  fmt.Println("generating zsk")
  pzsk, szsk := generateRSAKeyPair(p,session,"zsk",true,1024)
  _, zsk := CreateNewDNSKEY(
             zone,
             256,
             8, 
             minTTL, 
             b64.StdEncoding.EncodeToString(GetKeyBytes(p,session,pzsk)),
           )

  fmt.Println("generating ksk")
  pksk, sksk := generateRSAKeyPair(p,session,"ksk",true,2048)
  _, ksk := CreateNewDNSKEY(
             zone,
             257,
             8,  // RSASHA hardcoded, because I also like to live dangerously
             minTTL, // SOA -> minimum TTL
             b64.StdEncoding.EncodeToString(GetKeyBytes(p,session,pksk)),
           )
  defer DestroyAllKeys(p,session)
  fmt.Println("keys generated")

  fmt.Println("Start signing")
  zsksigner := rrSigner{p,session,szsk,pzsk}
  ksksigner := rrSigner{p,session,sksk,pksk}

  for i,v := range rrset {
    rrsig := CreateNewRRSIG(zone, zsk)
    err := rrsig.Sign(zsksigner,v)
    if err != nil { panic ("Error SignRR") }
    rrset[i] = append(rrset[i],rrsig)

    if (v[0].Header().Name == zone) {
      rrset[i] = append(rrset[i],zsk)
      zsksig := CreateNewRRSIG(zone,ksk)
      err := zsksig.Sign(ksksigner, rrset[i][len(rrset[i])-1:])
      if err != nil { panic ("Error SignRR KSK") }
      rrset[i] = append(rrset[i],zsksig)
      rrset[i] = append(rrset[i],ksk)
      sort.Sort(rrArray(rrset[i]))
    }
  }


  AddNSECRecords(rrset)

  
  PrintZone (rrset)
  return

/*
  _ = SearchValidKeys(p,session)
  fmt.Println(pksk,pzsk)
*/



}

