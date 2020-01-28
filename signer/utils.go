package signer

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
	"math/rand"
	"strings"
	"time"
)

// CreateNewDNSKEY creates a new DNSKEY RR, using the parameters provided.
func CreateNewDNSKEY(zone string, flags uint16, algorithm uint8, ttl uint32, publicKey string) *dns.DNSKEY {
	return &dns.DNSKEY{
		Flags:     flags,
		Protocol:  3, // RFC4034 2.1.2
		Algorithm: algorithm,
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		PublicKey: publicKey,
	}
}

// CreateNewRRSIG creates a new RRSIG RR, using the parameters provided.
func CreateNewRRSIG(zone string, dnsKeyRR *dns.DNSKEY, expDate time.Time, rrSetTTL uint32) *dns.RRSIG {
	if expDate.IsZero() {
		expDate = time.Now().AddDate(1, 0, 0)
	}
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			// Uses RRset TTL, not key TTL
			// (RFC4034, 3: The TTL value of an RRSIG RR MUST match the TTL value of the RRset it covers)
			Ttl: rrSetTTL,
		},
		Algorithm:  dnsKeyRR.Algorithm,
		SignerName: strings.ToLower(zone),
		KeyTag:     dnsKeyRR.KeyTag(),
		Inception:  uint32(time.Now().Unix()),
		Expiration: uint32(expDate.Unix()),
	}
}

// generateSalt returns a salt based on a random string seeded on current time.
func generateSalt() string {
	rand.Seed(time.Now().UnixNano())
	r := rand.Int31()
	s := fmt.Sprintf("%x", r)
	return s
}

// removeDuplicates removes the duplicates from an array of object handles.
func removeDuplicates(objs []pkcs11.ObjectHandle) []pkcs11.ObjectHandle {
	encountered := map[pkcs11.ObjectHandle]bool{}
	result := make([]pkcs11.ObjectHandle, 0)
	for _, o := range objs {
		if !encountered[o] {
			encountered[o] = true
			result = append(result, o)
		}
	}
	return result
}
