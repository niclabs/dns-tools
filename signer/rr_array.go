package signer

import (
	"fmt"
	"github.com/niclabs/dns"
	"io"
	"sort"
	"strings"
)

// RRArray represents an array of rrs
// It implements Swapper interface, and is sortable.
type RRArray []dns.RR

// RRArray is an array of RRArrays.
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

// Len returns the length of an RRSet.
func (rrSet RRSet) Len() int {
	return len(rrSet)
}

// Swap swaps elements on positions i and j from RRSet
func (rrSet RRSet) Swap(i, j int) {
	rrSet[i], rrSet[j] = rrSet[j], rrSet[i]
}

// Less returns true if the element in the position i of RRSet is less than the element in position j of RRSet.
func (rrSet RRSet) Less(i, j int) bool {
	iRRArray := rrSet[i]
	jRRArray := rrSet[j]
	if len(iRRArray) == 0 {
		if len(jRRArray) == 0 {
			return false
		} else {
			return true
		}
	}
	// Create and array to reuse Less method from rrArrays
	cmpArray := append(make(RRArray, 0), iRRArray[0], jRRArray[0])
	return cmpArray.Less(0, 1)
}

// writeZone prints on writer all the rrs on the array.
// The format of the text printed is the format of a DNS zone.
func (rrArray RRArray) writeZone(writer io.Writer) error {
	for _, rr := range rrArray {
		if _, err := fmt.Fprintln(writer, rr); err != nil {
			return err
		}
	}
	return nil
}

// createRRSet groups the rrs by rsaLabel and class if byType is false, or rsaLabel, class and type if byType is true
// NSEC/NSEC3 uses the version with byType = false, and RRSIG uses the other version.
// It assumes the rrarray is sorted.
func (rrArray RRArray) createRRSet(zone string, byType bool) (set RRSet) {
	// RRsets are RR grouped by rsaLabel and class for NSEC/NSEC3
	// and by rsaLabel, class, type for RRSIG:
	// An RRSIG record contains the signature for an RRset with a particular
	// name, class, and type. RFC4034
	set = make(RRSet, 0)
	nsNames := getAllNSNames(rrArray)
	var lastRR dns.RR
	for _, rr := range rrArray {
		if isSignable(rr, zone, nsNames) {
			if !sameRRSet(lastRR, rr, byType) {
				// create new set
				set = append(set, make(RRArray, 0))
			}
			// append to latest set
			set[len(set)-1] = append(set[len(set)-1], rr)
		}
		lastRR = rr
	}
	sort.Sort(set)
	return set
}

// addNSECRecords edits an RRArray and adds the respective NSEC records to it.
func (rrArray *RRArray) addNSECRecords(zone string) {

	set := rrArray.createRRSet(zone, false)

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

// addNSECRecords edits an RRArray and adds the respective NSEC3 records to it.
// If optOut is true, it sets the flag for NSEC3PARAM RR, following RFC5155 section 6.
// It returns an error if there is a colission on the hashes.
func (rrArray *RRArray) addNSEC3Records(zone string, optOut bool) error {
	set := rrArray.createRRSet(zone, false)

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
	// Sorting rrSets by name, class and type
	if collision {
		return fmt.Errorf("collision detected")
	}
	return nil
}

func getAllNSNames(rrArray RRArray) map[string]struct{} {
	m := make(map[string]struct{})
	for _, elem := range rrArray {
		if _, ok := elem.(*dns.NS); ok {
			m[dns.Fqdn(elem.Header().Name)] = struct{}{}
		}
	}
	return m
}

// isSignable returns true if the rr requires to be signed.
// The design of DNSSEC stipulates that delegations (non-apex NS records)
// are not signed, and neither are any glue records.
func isSignable(rr dns.RR, zone string, nsNames map[string]struct{}) bool {
	rrName := dns.Fqdn(rr.Header().Name)
	if _, ok := nsNames[rrName]; ok &&
		rrName != dns.Fqdn(zone) {
		return false
	}
	// It could be a IPv6 glue, too
	return true
}

// sameRRSet returns true if both rrs provided should be on the same RRSet.
func sameRRSet(rr1, rr2 dns.RR, byType bool) bool {
	if rr1 == nil || rr2 == nil {
		return false
	}
	return rr1.Header().Class == rr2.Header().Class &&
		strings.ToLower(dns.Fqdn(rr1.Header().Name)) == strings.ToLower(dns.Fqdn(rr2.Header().Name)) &&
		(!byType || rr1.Header().Rrtype == rr2.Header().Rrtype)
}

// isSignable checks if all the rrs are signable (they should be).
func (rrArray RRArray) isSignable(zone string, nsNames map[string]struct{}) bool {
	for _, rr := range rrArray {
		if !isSignable(rr, zone, nsNames) {
			return false
		}
	}
	return true
}
