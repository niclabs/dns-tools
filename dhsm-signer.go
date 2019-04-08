package main

import (
  "fmt"
  "os"
  . "github.com/miekg/pkcs11"
//  "github.com/miekg/dns"
)

func findObject(p *Ctx, session SessionHandle, label string) []ObjectHandle {
  template := []*(Attribute){
    NewAttribute(CKA_LABEL, label),
  }
  if err := p.FindObjectsInit(session, template); err != nil {
    panic("FindObjectsInit")
  }
  obj, _, err := p.FindObjects(session, 1024)
  if err != nil {
    panic("FindObjects")
  }
  if err := p.FindObjectsFinal(session); err != nil {
    panic("FindObjectsFinal")
  }
  if len(obj) > 0 {
    fmt.Println("found!")
    for _,o :=  range obj {
      att := []*(Attribute){
        NewAttribute(CKA_CLASS, label),
        NewAttribute(CKA_LABEL, label),
        NewAttribute(CKA_KEY_TYPE, label),
      }
      at,_ := p.GetAttributeValue(session,o,att)
      for _,a := range at {
        if (a.Type == 3) { fmt.Println(a.Type , string(a.Value)) 
        } else { fmt.Println(a.Type , a.Value) }
      }
    fmt.Println()
    }
  }
  return obj
}

func generateRSAKeyPair(p *Ctx, session SessionHandle, tokenLabel string, tokenPersistent bool, bits int) (ObjectHandle, ObjectHandle) {

  publicKeyTemplate := []*Attribute{
    NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
    NewAttribute(CKA_KEY_TYPE, CKK_RSA),
    NewAttribute(CKA_TOKEN, tokenPersistent),
    NewAttribute(CKA_VERIFY, true),
    NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
    NewAttribute(CKA_MODULUS_BITS, bits),
    NewAttribute(CKA_LABEL, tokenLabel),
  }
  
  privateKeyTemplate := []*Attribute{
    NewAttribute(CKA_TOKEN, tokenPersistent),
    NewAttribute(CKA_SIGN, true),
    NewAttribute(CKA_LABEL, tokenLabel),
    NewAttribute(CKA_SENSITIVE, true),
    NewAttribute(CKA_EXTRACTABLE, true),
  }

  pbk, pvk, e := p.GenerateKeyPair(session,
    []*Mechanism{NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
    publicKeyTemplate, privateKeyTemplate)
  if e != nil {
    panic("failed to generate keypair")
  }
  return pbk, pvk
}

func main() {
  args := os.Args[1:]
  zonefile := "example.com"
  pkcs11lib := "/usr/local/lib/libpkcs11.so"

  if (len(args) > 2) {
    fmt.Println("Usage: " + os.Args[0] + " [zonefile] [pkcs11-lib]")
    return
    } else if (len(args) < 2) {
    zonefile = args[0]
  }  else {
    zonefile = args[0]
    pkcs11lib = args[1]
  }
  fmt.Println(zonefile + " " + pkcs11lib)

  p := New(pkcs11lib)

  err := p.Initialize()
  if err != nil {
    panic(err)
    fmt.Println("Has the .db RW permission?")
  }
  defer p.Destroy()
  defer p.Finalize()
  slots, err := p.GetSlotList(true)
  if err != nil {
      panic(err)
  }

  info, err := p.GetInfo()
  if err != nil {
    panic("GetInfo error")
  }
  fmt.Println("HSM Info: \n", info)
 
  for s := range slots {
    fmt.Println("Slot",s,"info:")
    slot_info, _ := p.GetSlotInfo(uint(s))
    fmt.Printf("%+v\n",slot_info)
    fmt.Println()
  }
  session, err := p.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
  if err != nil {
    panic(err)
  }
  defer p.CloseSession(session)

  /*
  token_info, err := p.GetTokenInfo(slots[0])
  if err != nil {
    panic(err)
  }
  fmt.Printf("%+v\n",token_info) 
*/
  err = p.Login(session, CKU_USER, "1234")
  if err != nil {
      panic(err)
  }
  defer p.Logout(session)

  fmt.Println("Creating keys...")
  _,_ = generateRSAKeyPair(p,session,"ksk",true,1024)

  fmt.Println("Keys created... deleting")
  objs := findObject(p,session,"ksk")
  for i,_ := range objs {
    if e := p.DestroyObject(session, objs[i]); e != nil {
      fmt.Println("Destroy Key failed", e)
    }
  }
}

