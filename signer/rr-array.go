package signer

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
	"sort"
	"strings"
)

// RRArray represents an array of RRs
// It implements Swapper interface, and is sortable.
type RRArray []dns.RR

// RRSet is an array of RRArrays.
type RRSet []RRArray

// Len returns the length of an RRArray.
func (rrArray RRArray) Len() int {
	return len(rrArray)
}

// Swap swaps elements on positions i and j from RRArray
func (rrArray RRArray) Swap(i, j int) {
	rrArray[i], rrArray[j] = rrArray[j], rrArray[i]
}

// Less returns true if the element in the position i of RRArray is less than the element in position j of RRArray.
func (rrArray RRArray) Less(i, j int) bool {
	si := strings.Split(strings.ToLower(rrArray[i].Header().Name), ".")
	sj := strings.Split(strings.ToLower(rrArray[j].Header().Name), ".")
	if len(si) < len(sj) || len(si) > len(sj) {
		return len(si) < len(sj)
	}
	// Equal length, check from left to right omiting .[nothing]
	for k := len(si) - 2; k >= 0; k-- {
		if si[k] < sj[k] {
			return true
		} else if si[k] > sj[k] {
			return false
		}
	}
	if rrArray[i].Header().Class == rrArray[j].Header().Class {
		return rrArray[i].Header().Rrtype < rrArray[j].Header().Rrtype
	} else {
		return rrArray[i].Header().Class < rrArray[j].Header().Class
	}
}

// PrintZone prints on stdout all the RRs on the array.
// The format of the text printed is the format of a DNS zone.
func (rrArray RRArray) PrintZone() {
	for _, rr := range rrArray {
		fmt.Println(rr)
	}
}

// CreateRRSet groups the RRs by label and class if byType is false, or label, class and type if byType is true
// NSEC/NSEC3 uses the version with byType = false, and RRSIG uses the other version.
func (rrArray RRArray) CreateRRSet(byType bool) RRSet {
	// RRsets are RR grouped by label and class for NSEC/NSEC3
	// and by label, class, type for RRSIG:
	// An RRSIG record contains the signature for an RRset with a particular
	// name, class, and type. RFC4034

	rr := rrArray[0]
	set := make(RRSet, 0, 32)
	set = append(set, make(RRArray, 0, 32))
	set[0] = append(set[0], rr)
	i := 0
	for k := 1; k < len(rrArray); k++ {
		h0 := rr.Header()
		h1 := rrArray[k].Header()
		if !(h0.Class == h1.Class && strings.ToLower(h0.Name) == strings.ToLower(h1.Name) && (!byType || h0.Rrtype == h1.Rrtype)) {
			i = i + 1
			rr = rrArray[k]
			set = append(set, make(RRArray, 0, 32))
		}
		set[i] = append(set[i], rrArray[k])
	}
	return set
}

// AddNSECRecords edits an RRArray and adds the respective NSEC records to it.
func (rrArray *RRArray) AddNSECRecords() {

	set := rrArray.CreateRRSet(false)

	n := len(set)
	for i, rrs := range set {
		typeMap := make(map[uint16]bool)
		typeArray := make([]uint16, 0)
		for _, rr := range rrs {
			typeMap[rr.Header().Rrtype] = true
		}
		typeMap[dns.TypeNSEC] = true

		for k := range typeMap {
			typeArray = append(typeArray, k)
		}

		sort.Slice(typeArray, func(i, j int) bool {
			return typeArray[i] < typeArray[j]
		})

		nsec := &dns.NSEC{}
		nsec.Hdr.Name = rrs[0].Header().Name
		nsec.Hdr.Rrtype = dns.TypeNSEC
		nsec.Hdr.Class = dns.ClassINET
		nsec.Hdr.Ttl = rrs[0].Header().Ttl
		nsec.NextDomain = set[(i+1)%n][0].Header().Name
		nsec.TypeBitMap = typeArray

		*rrArray = append(*rrArray, nsec)
	}

	sort.Sort(*rrArray)
}

// AddNSECRecords edits an RRArray and adds the respective NSEC3 records to it.
// If optOut is true, it sets the flag for NSEC3PARAM RR, following RFC5155 section 6.
func (rrArray *RRArray) AddNSEC3Records(optOut bool) {
	set := rrArray.CreateRRSet(false)

	h := make(map[string]bool)
	collision := false

	param := &dns.NSEC3PARAM{}
	param.Hdr.Class = dns.ClassINET
	param.Hdr.Rrtype = dns.TypeNSEC3PARAM
	param.Hash = dns.SHA1
	if optOut {
		param.Flags = 1
	}
	param.Iterations = 100 // 100 is enough!
	param.Salt = generateSalt()
	// Possible library bug: for some reason the library does not parse the value in NSEC3PARAM as octets, but RFC5155 4.2
	// specifies that the behaviour of this field is the same as NSEC3 case (3.1.4).
	param.SaltLength = uint8(len(param.Salt))
	apex := ""
	minttl := uint32(8600)

	n := len(set)
	last := -1

	for _, rrs := range set {
		typeMap := make(map[uint16]bool)
		for _, rr := range rrs {
			typeMap[rr.Header().Rrtype] = true

			if rr.Header().Rrtype == dns.TypeSOA {
				param.Hdr.Name = rr.Header().Name
				apex = rr.Header().Name
				minttl = rr.(*dns.SOA).Minttl
				param.Hdr.Ttl = minttl
				typeMap[dns.TypeNSEC3PARAM] = true
			}
		}
		if optOut && !typeMap[dns.TypeDS] && !typeMap[dns.TypeDNSKEY] {
			continue
		}

		typeArray := make([]uint16, 0)
		for k := range typeMap {
			typeArray = append(typeArray, k)
		}

		sort.Slice(typeArray, func(i, j int) bool {
			return typeArray[i] < typeArray[j]
		})
		
		nsec3 := &dns.NSEC3{}
		nsec3.Hdr.Class = dns.ClassINET
		nsec3.Hdr.Rrtype = dns.TypeNSEC3
		nsec3.Hash = param.Hash
		nsec3.Flags = param.Flags
		nsec3.Iterations = param.Iterations
		nsec3.SaltLength = uint8(len(param.Salt)) / 2 // length is in octets and salt is an hex value.
		nsec3.Salt = param.Salt
		hName := dns.HashName(rrs[0].Header().Name, param.Hash,
			param.Iterations, param.Salt)

		if h[hName] {
			collision = true
			last = -1
			break
		}
		h[hName] = true

		nsec3.Hdr.Name = hName
		nsec3.TypeBitMap = typeArray

		if last >= 0 { // not the first NSEC3 record
			set[n+last][0].(*dns.NSEC3).NextDomain = nsec3.Hdr.Name
			set[n+last][0].(*dns.NSEC3).HashLength = 20 // It's the length of the hash, not the encoding
		}
		last = last + 1

		set = append(set, RRArray{nsec3})
	}

	if last >= 0 {
		set[n+last][0].(*dns.NSEC3).NextDomain = set[n][0].Header().Name
		set[n+last][0].(*dns.NSEC3).HashLength = 20 // It's the length of the hash, not the encoding

		for i := n; i < len(set); i++ {
			set[i][0].Header().Name = set[i][0].Header().Name + "." + apex
			set[i][0].Header().Ttl = minttl
			*rrArray = append(*rrArray, set[i][0])
		}

		*rrArray = append(*rrArray, param)
		sort.Sort(*rrArray)
	}

	if collision { // all again
		_, _ = fmt.Fprintf(os.Stderr, "Collision detected, NSEC3-ing all again\n")
		rrArray.AddNSEC3Records(optOut)
	}
}
