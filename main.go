package main

import (
  "fmt"
  b64 "encoding/base64"
  "sort"
  "os"
)

func main() {

  p, session, zone, zfile, create_keys, nsec3, optout := init_dHSMsigner()
  defer p.Destroy()
  defer p.Finalize()
  defer p.CloseSession(session)
  defer p.Logout(session)

  if zone[len(zone)-1] != '.' { zone = zone + "."}

  rrset, minTTL := ReadAndParseZone(zfile)

  // bkeys = {pzsk, szsk, pksk, sksk}
  keys, bkeys := SearchValidKeys(p,session)
  pzsk := keys[0]
  szsk := keys[1]
  pksk := keys[2]
  sksk := keys[3]
  
  if (create_keys || !bkeys[0] || !bkeys[2] ) {
     
    if create_keys && bkeys[0] { 
      ExpireKey(p,session,pzsk) 
      ExpireKey(p,session,szsk) 
    }
    if create_keys || !bkeys[0] {
      fmt.Fprintf(os.Stderr,"generating zsk\n")
      pzsk, szsk = generateRSAKeyPair(p,session,"zsk",true,1024)
    }
    if create_keys && bkeys[2] { 
      ExpireKey(p,session,pksk) 
      ExpireKey(p,session,sksk) 
    }
    if create_keys || !bkeys[2]  {
      fmt.Fprintf(os.Stderr,"generating ksk\n")
      pksk, sksk = generateRSAKeyPair(p,session,"ksk",true,2048)
    }
    fmt.Fprintf(os.Stderr,"keys generated\n")
  }
//  defer DestroyAllKeys(p,session)

  zsk := CreateNewDNSKEY(
         zone,
         256,
         8, 
         minTTL, 
         b64.StdEncoding.EncodeToString(GetKeyBytes(p,session,pzsk)),
       )
  ksk := CreateNewDNSKEY(
         zone,
         257,
         8,  // RSASHA hardcoded, because I also like to live dangerously
         minTTL, // SOA -> minimum TTL
         b64.StdEncoding.EncodeToString(GetKeyBytes(p,session,pksk)),
       )

  if (nsec3) {
    AddNSEC3Records(&rrset,optout)
  } else {
    AddNSECRecords(rrset)
  }

  fmt.Fprintf(os.Stderr,"Start signing\n")
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
  
  fmt.Fprintf(os.Stderr,"DS: %s\n", ksk.ToDS(1)) // SHA256

  PrintZone (rrset)
  return

}

