package main

import (
  "fmt"
  "flag"
  "os"
  . "github.com/miekg/pkcs11"
)

func init_dHSMsigner() (*Ctx, SessionHandle, string, string, bool) {

  zone := flag.String("zone","","zone name")
  file := flag.String("file","","full path to zone file to be signed")
  p11lib :=  flag.String("p11lib","","full path to pkcs11 lib file")
  rk := flag.Bool("renew_keys",false,"create a new set of keys for signing")

  flag.Parse()

  if len(*zone) < 1 || len(*file) < 1 || len(*p11lib) < 1 {
    fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
    flag.PrintDefaults()
    os.Exit(1)
  }

  _, perr := os.Stat(*file)
  if perr != nil || os.IsNotExist(perr) {
    fmt.Fprintf(os.Stderr, "Error file %s doesn't exists or has not reading permission\n", *file)
    os.Exit(1)
  }

  p := New(*p11lib)
  if p == nil {
    fmt.Fprintf(os.Stderr, "Error initializing %s\n",*p11lib)
    panic("File not found")
  }

  err := p.Initialize()
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error initializing %s\n",*p11lib)
    fmt.Fprintf(os.Stderr, "Has the .db RW permission?")
    panic(err)
  }

  slots, err := p.GetSlotList(true)
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error checking slots\n")
    panic(err)
  }

  info, err := p.GetInfo()
  if err != nil {
    panic("GetInfo error")
  }
  fmt.Println("HSM Info: \n", info)

  session, err := p.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error creating session\n")
    panic(err)
  }

  err = p.Login(session, CKU_USER, "1234")
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error login with default key 1234\n")
    panic(err)
  }

  return p,session,*zone,*file,*rk
}

