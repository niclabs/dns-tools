package main

import (
  "fmt"
  "io"
  "time"
  . "github.com/miekg/pkcs11"
  "crypto"
  "crypto/rsa"
  "crypto/x509"
  "math/big"
)


func removeDuplicates(objs []ObjectHandle) []ObjectHandle {
  encountered := map[ObjectHandle]bool{}
  result := []ObjectHandle{}
  for _, o := range objs {
    if !encountered[o]  {
      encountered[o] = true
      result = append(result, o)
    }
  }
  return result
}

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
  return removeDuplicates(obj)
}

func generateRSAKeyPair(p *Ctx, session SessionHandle, tokenLabel string, tokenPersistent bool, bits int) (ObjectHandle, ObjectHandle) {

  today := time.Now()
  nextyear := today.AddDate(1,0,0)

  publicKeyTemplate := []*Attribute{
    NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
    NewAttribute(CKA_LABEL, "dHSM-signer"),
    NewAttribute(CKA_ID, []byte(tokenLabel)),
    NewAttribute(CKA_KEY_TYPE, CKK_RSA),
    NewAttribute(CKA_TOKEN, tokenPersistent),
    NewAttribute(CKA_START_DATE, today),
    NewAttribute(CKA_END_DATE, nextyear),
    NewAttribute(CKA_VERIFY, true),
    NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
    NewAttribute(CKA_MODULUS_BITS, bits),
  }
  
  privateKeyTemplate := []*Attribute{
    NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
    NewAttribute(CKA_LABEL, "dHSM-signer"),
    NewAttribute(CKA_ID, []byte(tokenLabel)),
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


// return the public key in ASN.1 DER form

func GetKeyBytes(p *Ctx, session SessionHandle,o ObjectHandle) []byte {
  pk := rsa.PublicKey{N: big.NewInt(0), E: 0}
  PKTemplate := []*Attribute{
    NewAttribute(CKA_MODULUS,nil),
    NewAttribute(CKA_PUBLIC_EXPONENT,nil),
    }
  attr, err := p.GetAttributeValue(session,o,PKTemplate)
  if err != nil {
    fmt.Println("Attributes  failed", err)
    return nil
  } else {
    pk.N.SetBytes(attr[0].Value)
    e := big.NewInt(0)
    e.SetBytes(attr[1].Value)
    pk.E = int(e.Int64())
  }
  return x509.MarshalPKCS1PublicKey(&pk)
}


// Sign an RR set
type rrSigner struct { 
  p *Ctx
  session SessionHandle
  sk, pk ObjectHandle
  }

func (rs rrSigner) Public() crypto.PublicKey {
  return crypto.PublicKey(rs.pk)
  }

func (rs rrSigner) Sign(rand io.Reader, rr []byte, opts crypto.SignerOpts) ([]byte, error) {

  m := []*Mechanism{NewMechanism(CKM_SHA256_RSA_PKCS, nil)}
  e:= rs.p.SignInit(rs.session, m, rs.sk)
  if e != nil {
    fmt.Println("failed to init sign:", e)
    return nil, e
  } 
 
  s, e := rs.p.Sign(rs.session, rr)
  if e != nil {
    fmt.Println("failed to sign:", e)
    return nil, e
  } 
  return s, nil
}

func SearchValidKeys(p *Ctx, session SessionHandle) []ObjectHandle {

  AllTemplate := []*Attribute{
    NewAttribute(CKA_LABEL, "dHSM-signer"),
  }
  DateTemplate := []*Attribute{
    NewAttribute(CKA_ID, nil),
    NewAttribute(CKA_ID, nil),
    NewAttribute(CKA_START_DATE, nil),
    NewAttribute(CKA_END_DATE, nil),
  }
  objs := findObject(p,session,AllTemplate)
  valid_keys := []ObjectHandle {}

  if len(objs) > 0 {
    t := time.Now()
    sToday := fmt.Sprintf("%d%02d%02d",t.Year(),t.Month(), t.Day())
    fmt.Println("Keys found... checking validity")
    for _, o := range objs {
      attr, err := p.GetAttributeValue(session,o,DateTemplate)
      if err != nil {
        fmt.Println("Attributes  failed", err)
      } else {
        for _, a := range attr {
          fmt.Println(a.Type, string(a.Value),sToday)
          if a.Type == 273 && string(a.Value) > sToday {
            valid_keys = append(valid_keys,o)
          }
        }
      }
    }
  } else {
    fmt.Println("No keys found :-/")
  }
  return valid_keys
}


func DestroyAllKeys(p *Ctx, session SessionHandle) {
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


