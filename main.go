package main

import (
  "fmt"
//.  . "github.com/miekg/pkcs11"
  . "github.com/miekg/dns"
  "encoding/gob"
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

  fmt.Println("Signing...",zfile,"for",zone,"with reset keys =",reset_keys)

  rrmap := ReadAndParseZone(zfile)

/*
  fmt.Println("generating ksk")
  pksk, _ := generateRSAKeyPair(p,session,"ksk",true,2048)
*/
  fmt.Println("generating zsk")
  _, szsk := generateRSAKeyPair(p,session,"zsk",true,1024)
  fmt.Println("key generated")

  s := SignRR(p, session, GetBytes(rrmap[TypeA]), szsk)
  if s == nil {
    fmt.Println("SignRR failed")
    } 
  fmt.Println("signature:", rrmap[TypeA],s)

  defer DestroyAllKeys(p,session)


/*
  _ = SearchValidKeys(p,session)
  fmt.Println(pksk,pzsk)
*/



}

