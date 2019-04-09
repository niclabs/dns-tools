package main

import (
  "fmt"
  "time"
  . "github.com/miekg/pkcs11"
)

func findObject(p *Ctx, session SessionHandle, template []*(Attribute)) []ObjectHandle {
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
/*
  if len(obj) > 0 {
    fmt.Println("found!")
    for _,o :=  range obj {
      fmt.Println("Object = ",o)
    }
    fmt.Println()
  }
*/
  return obj
}

func generateRSAKeyPair(p *Ctx, session SessionHandle, tokenLabel string, tokenPersistent bool, bits int) (ObjectHandle, ObjectHandle) {

  today := time.Now()
  nextyear := today.AddDate(1,0,0)

  publicKeyTemplate := []*Attribute{
    NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
    NewAttribute(CKA_LABEL, "dHSM-signer"),
    NewAttribute(CKA_KEY_TYPE, CKK_RSA),
    NewAttribute(CKA_TOKEN, tokenPersistent),
    NewAttribute(CKA_START_DATE, today),
    NewAttribute(CKA_END_DATE, nextyear),
    NewAttribute(CKA_ENCRYPT, true),
    NewAttribute(CKA_VERIFY, true),
    NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
    NewAttribute(CKA_MODULUS_BITS, bits),
  }
  
  privateKeyTemplate := []*Attribute{
    NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
    NewAttribute(CKA_LABEL, "dHSM-signer"),
    NewAttribute(CKA_KEY_TYPE, CKK_RSA),
    NewAttribute(CKA_TOKEN, tokenPersistent),
    NewAttribute(CKA_START_DATE, today),
    NewAttribute(CKA_END_DATE, nextyear),
    NewAttribute(CKA_SIGN, true),
    NewAttribute(CKA_SENSITIVE, true),
    NewAttribute(CKA_PRIVATE, true),
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

func SearchValidKeys(p *Ctx, session SessionHandle) []ObjectHandle {

  AllTemplate := []*Attribute{
    NewAttribute(CKA_LABEL, "dHSM-signer"),
  }
  DateTemplate := []*Attribute{
    NewAttribute(CKA_START_DATE, nil),
    NewAttribute(CKA_END_DATE, nil),
  }
  objs := findObject(p,session,AllTemplate)

  if len(objs) > 0 {
    fmt.Println("Keys found... checking validity")
    for _, o := range objs {
      attr, err := p.GetAttributeValue(session,o,DateTemplate)
      if err != nil {
        fmt.Println("Attributes  failed", err)
      } else {
        for _, a := range attr {
          fmt.Println(string(a.Value))
        }
      }
    }
  } else {
    fmt.Println("Keys not found :-/")
  }
  return objs
}


func SearchAndDestroy(p *Ctx, session SessionHandle) {
  deleteTemplate := []*Attribute{
    NewAttribute(CKA_LABEL, "dHSM-signer"),
  }
  objs2 := findObject(p,session,deleteTemplate)
  
  if len(objs2) > 0 {
    fmt.Println("Keys found... deleting")
    for _,o := range objs2 {
      if e := p.DestroyObject(session, o); e != nil {
        fmt.Println("Destroy Key failed", e)
      }
    }
  } else {
    fmt.Println("Keys not found :-/")
  }
}


