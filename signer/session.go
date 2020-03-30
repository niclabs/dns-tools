package signer

import (
	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
	"time"
)

type Session interface {
	Sign() (ds *dns.DS, err error)
	End() error
	DestroyAllKeys() error
}

// Key represents a structure with a handle and an expiration date.
type Key struct {
	Handle  pkcs11.ObjectHandle // Handle related with the key
	ExpDate time.Time           // Expiration Date of the key
}

// SignatureKeys contains the four keys used in zone signing.
type SignatureKeys struct {
	PublicZSK, PrivateZSK *Key
	PublicKSK, PrivateKSK *Key
}
