package main

import (
  "fmt"
  "flag"
  "os"
  . "github.com/miekg/pkcs11"
)

func init_dHSMsigner() (*Ctx, SessionHandle, string, string, bool) {

  rk := flag.Bool("reset_keys",false,"remove all keys and exit")
  ck := flag.Bool("create_keys",false,"create a new pair of keys, outdading all valid keys. Default: first try to find valid keys.")
  zone := flag.String("zone","","zone name")
  file := flag.String("file","","full path to zone file to be signed")
  p11lib :=  flag.String("p11lib","","full path to pkcs11 lib file")

  flag.Parse()

  if len(*p11lib) < 1 {
    fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
    fmt.Fprintf(os.Stderr, "%s -p11lib pkcs11_lib --reset_keys\n", os.Args[0])
    fmt.Fprintf(os.Stderr, "%s -p11lib pkcs11_lib -zone name -file filezon [--create_keys]\n",os.Args[0])
    flag.PrintDefaults()
    os.Exit(1)
  }

  if !*rk {
    if len(*zone) < 1 || len(*file) < 1  {
      fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
      flag.PrintDefaults()
      os.Exit(1)
    } 

    _, perr := os.Stat(*file)
    if perr != nil || os.IsNotExist(perr) {
      fmt.Fprintf(os.Stderr, "Error file %s doesn't exists or has not reading permission\n", *file)
      os.Exit(1)
    }
  }
  p := New(*p11lib)
  if p == nil {
    fmt.Fprintf(os.Stderr, "Error initializing %s\n",*p11lib)
    panic("File not found")
  }

  err := p.Initialize()
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error initializing %s\n",*p11lib)
    fmt.Fprintf(os.Stderr, "Has the .db RW permission?\n")
    panic(err)
  }

  slots, err := p.GetSlotList(true)
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error checking slots\n")
    panic(err)
  }

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

  if (*rk) {
    DestroyAllKeys(p,session)
    p.Logout(session)
    p.CloseSession(session)
    p.Finalize()
    p.Destroy()
    fmt.Fprintf(os.Stderr, "All keys destroyed\n")
    os.Exit(1)
  }
  return p,session,*zone,*file,*ck
}

