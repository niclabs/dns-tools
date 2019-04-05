package main

import (
  "fmt"
  "os"

//  "github.com/miekg/dns"
  "github.com/miekg/pkcs11"
)

func main() {
  args := os.Args[1:]
  zonefile := "example.com"
  pkcs11lib := "/usr/local/bin/pkcs11.so"

  if (len(args) > 2) {
    fmt.Println("Usage: " + os.Args[0] + " [zonefile] [pkcs11-lib]")
    return
    } else if (len(args) < 2) {
    zonefile = args[0]
  }  else {
    zonefile = args[0]
    pkcs11lib = args[1]
  }
  fmt.Println(zonefile + " " + pkcs11lib)

  p := pkcs11.New(pkcs11lib)

  slots, err := p.GetSlotList(true)
    if err != nil {
        panic(err)
    }
  session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
    if err != nil {
        panic(err)
    }
    defer p.CloseSession(session)

    err = p.Login(session, pkcs11.CKU_USER, "1234")
    if err != nil {
        panic(err)
    }
    defer p.Logout(session)

    p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
    hash, err := p.Digest(session, []byte("this is a string"))
    if err != nil {
        panic(err)
    }

    for _, d := range hash {
            fmt.Printf("%x", d)
    }
    fmt.Println()
}

