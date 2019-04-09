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
  if len(obj) > 0 {
    fmt.Println("found!")
    for _,o :=  range obj {
      att := []*(Attribute){
        NewAttribute(CKA_CLASS, nil),
        NewAttribute(CKA_LABEL, nil),
        NewAttribute(CKA_KEY_TYPE, nil),
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

  currentTime := time.Now()
  nextTear := currentTime.AddDate(1,0,0)

  
  publicKeyTemplate := []*Attribute{
    NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
    NewAttribute(CKA_LABEL, "dHSM-signer"),
    NewAttribute(CKA_KEY_TYPE, CKK_RSA),
    NewAttribute(CKA_TOKEN, tokenPersistent),
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

func SearchAndDestroy(p *Ctx, session SessionHandle) {
  deleteTemplate := []*Attribute{
    NewAttribute(CKA_LABEL, "dHSM-signer"),
  }
  objs := findObject(p,session,deleteTemplate)
  
  if len(objs) > 0 {
    fmt.Println("Keys found... deleting")
    for i,_ := range objs {
      if e := p.DestroyObject(session, objs[i]); e != nil {
        fmt.Println("Destroy Key failed", e)
      }
    }
  } else {
    fmt.Println("Keys not found :-/")
  }
}


