package signer

/* leer la zona 
   agregar ZONEMD con 00s de digest
   ordenar zona
   firmar zona
   update ZONEMD
   recalcular RRSIG de ZONEMD y actualizar (o agregar?)
   recalcular DS?
   ojo que SOA y ZONEMD deben ser el mismo en la zona a publicar */


import (
	"crypto/sha512"
  "encoding/hex"
	"github.com/niclabs/dns"
	)


func CalculateDigest(rrs RRArray) (string, error) {
  h := sha512.New384()

	buf := make([]byte, dns.MaxMsgSize)
  for _, rr := range rrs {
		size, err := dns.PackRR(rr, buf, 0, nil, false)
		if err == nil {
			return "", err
		}
		h.Write(buf[:size])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
