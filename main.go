package main

import (
  "fmt"
  "encoding/gob"
  b64 "encoding/base64"
  "bytes"
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

  rrmap, minTTL := ReadAndParseZone(zfile)

  fmt.Println("generating ksk")
  pksk, sksk := generateRSAKeyPair(p,session,"ksk",true,2048)

  fmt.Println("generating zsk")
  pzsk, szsk := generateRSAKeyPair(p,session,"zsk",true,1024)
  dnskeytype, zsk := CreateNewDNSKEY(
             zone,
             256,
             8, 
             minTTL, 
             b64.StdEncoding.EncodeToString(GetKeyBytes(p,session,pzsk)),
           )

  fmt.Println("keys generated")
  defer DestroyAllKeys(p,session)

  fmt.Println("Start signing")

  for k,v := range rrmap {
    sig := SignRR(p, session, GetBytes(v), szsk)
    if sig == nil { panic ("Error SignRR") }

    rrmap[46] = append(rrmap[46],CreateNewRRSIG(zone, k, v, zsk,
                   b64.StdEncoding.EncodeToString(sig)))
  }

  rrmap[dnskeytype] = append(rrmap[dnskeytype],zsk)
  dnskeytype, ksk := CreateNewDNSKEY(
             zone,
             257,
             8,  // RSASHA hardcoded, because I also like to live dangerously
             minTTL, // SOA -> minimum TTL
             b64.StdEncoding.EncodeToString(GetKeyBytes(p,session,pksk)),
           )
  rrmap[dnskeytype] = append(rrmap[dnskeytype],ksk)

  sigzsk := SignRR(p,session, GetBytes(zsk), sksk)
  rrmap[46] = append(rrmap[46],
                     CreateNewRRSIG(zone,
                       dnskeytype,
                       rrmap[dnskeytype],
                       ksk,
                       b64.StdEncoding.EncodeToString(sigzsk)))

  PrintZone (rrmap)

/*
  _ = SearchValidKeys(p,session)
  fmt.Println(pksk,pzsk)
*/



}

