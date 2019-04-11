package main

import (
  "fmt"
//  . "github.com/miekg/pkcs11"
//  . "github.com/miekg/dns"
)

func main() {

  p, session, zone, zfile, reset_keys := init_dHSMsigner()
  defer p.Destroy()
  defer p.Finalize()
  defer p.CloseSession(session)
  defer p.Logout(session)

  fmt.Println("Signing...",zfile,"for",zone,"with reset keys =",reset_keys)

  ReadAndParseZone(zfile)
  return;

  generateRSAKeyPair(p,session,"ksk",true,1024)
  defer DestroyAllKeys(p,session)

  fmt.Println("key generated")

  _ = SearchValidKeys(p,session)

}

