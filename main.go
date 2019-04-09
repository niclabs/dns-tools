package main

import (
  "fmt"
//  . "github.com/miekg/pkcs11"
//  . "github.com/miekg/dns"
)

func main() {

  p, session, zone, zfile, reuse_keys := init_dHSMsigner()
  defer p.Destroy()
  defer p.Finalize()
  defer p.CloseSession(session)
  defer p.Logout(session)

  if (reuse_keys) { 
    fmt.Println("Check if there are available keys for ...",zone)
  }
  fmt.Println("Signing...",zfile)

  generateRSAKeyPair(p,session,"ksk",true,1024)
  defer SearchAndDestroy(p,session)

  fmt.Println("key generated")

  _ = SearchValidKeys(p,session)

}

