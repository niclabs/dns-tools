package tools

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
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

// generateSalt returns a 64 bit salt from a cryptographically secure generator.
func generateSalt() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
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

// rsaPublicKeyToBytes transforms an RSA Public key to formatted bytes, usable in zone signing
func rsaPublicKeyToBytes(exponent, modulus []byte) ([]byte, error) {
	if len(exponent) > 8 {
		return nil, fmt.Errorf("exponent length is larger than 8 bytes")
	}
	if len(exponent) == 0 {
		return nil, fmt.Errorf("exponent is zero")
	}
	n := uint32(len(exponent))
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, n)
	// Stores as BigEndian, read as LittleEndian, what could go wrong?
	if n < 256 {
		a = a[3:]
	} else if n <= 512 {
		a = a[1:]
	} else {
		return nil, fmt.Errorf("invalid exponent length. Its size must be between 1 and 4096 bits")
	}

	a = append(a, exponent...)
	a = append(a, modulus...)

	return a, nil

}

func ecdsaPublicKeyToBytes(ecPoint []byte) ([]byte, error) {
	curve := elliptic.P256()
	curveBytes := 2 * int((curve.Params().BitSize+7)/8)
	// asn1 -> elliptic-marshaled
	asn1Encoded := make([]byte, 0)
	rest, err := asn1.Unmarshal(ecPoint, &asn1Encoded)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("corrupted public key")
	}
	x, y := elliptic.Unmarshal(curve, asn1Encoded)
	if x == nil {
		return nil, fmt.Errorf("error decoding point")
	}
	// elliptic-marshaled -> elliptic.pubkey
	bytesPoint := make([]byte, curveBytes) // two 32 bit unsigned numbers
	xBytes, yBytes := x.Bytes(), y.Bytes()
	copy(bytesPoint[curveBytes/2-len(xBytes):curveBytes/2], xBytes)
	copy(bytesPoint[curveBytes-len(yBytes):curveBytes], yBytes)
	return bytesPoint, nil
	// elliptic.pubkey -> {x|y}

}

func newTypeArray(typeMap map[uint16]bool) []uint16 {
	typeArray := make([]uint16, 0)
	for k := range typeMap {
		typeArray = append(typeArray, k)
	}

	sort.Slice(typeArray, func(i, j int) bool {
		return typeArray[i] < typeArray[j]
	})
	return typeArray
}
