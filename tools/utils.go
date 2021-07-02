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
	"unicode"

	"github.com/miekg/dns"
	"github.com/twotwotwo/sorts"
)

// CreateNewRRSIG creates a new RRSIG RR, using the parameters provided.
func CreateNewRRSIG(zone string, dnsKeyRR *dns.DNSKEY, expDate time.Time, rrSetTTL uint32) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			// Uses RRset TTL, not key TTL
			// (RFC4034, 3: The TTL value of an RRSIG RR MUST match the TTL value of the RRset it covers)
			Ttl: rrSetTTL,
		},
		Algorithm:  dnsKeyRR.Algorithm,
		SignerName: zone,
		KeyTag:     dnsKeyRR.KeyTag(),
		Inception:  uint32(time.Now().Unix()),
		Expiration: uint32(expDate.Unix()),
	}
}

// NormalizeFQDN normalizes a fqdn to ASCII (lower-case punycode).
func NormalizeFQDN(fqdn string) string {
	fqdn = strings.ToLower(fqdn)
	for i := 0; i < len(fqdn); i++ {
		if fqdn[i] > unicode.MaxASCII {
			panic(fmt.Errorf("non-ascii character in a name: %c", fqdn[i]))
		}
	}
	return fqdn
}

func generateSalt(length uint8) (string, error) {
	if length > 64 {
		length = 64
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
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
	// RRSIG byte is added just in case
	typeMap[dns.TypeRRSIG] = true
	typeArray := make([]uint16, 0)
	// Then we add the types present in typeMap
	for k := range typeMap {
		typeArray = append(typeArray, k)
	}

	sort.Slice(typeArray, func(i, j int) bool {
		return typeArray[i] < typeArray[j]
	})
	return typeArray
}

func quickSort(sortable sort.Interface) {
	sorts.Quicksort(sortable)
}

func getHash(rr dns.RR, byType bool) string {
	hash := fmt.Sprintf("%s#%s", rr.Header().Name, dns.Class(rr.Header().Class))
	if byType {
		hash += fmt.Sprintf("#%s", dns.Type(rr.Header().Rrtype))
	}
	return hash
}

func getRRSIGHash(rr *dns.RRSIG) string {
	return fmt.Sprintf("%s#%s#%s", rr.Header().Name, dns.Class(rr.Header().Class), dns.Type(rr.TypeCovered))
}

func (ctx *Context) isSignable(ownerName string) bool {
	_, isDS := ctx.WithDS[ownerName]
	return ctx.Config.OptOut || !ctx.isDelegated(ownerName) || isDS
}
