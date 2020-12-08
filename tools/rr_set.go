package tools

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// RRArray represents an array of rrs
// It implements Swapper interface, and is sortable.
type RRArray []dns.RR

// RRSetList is an array of RRArrays.
type RRSetList []RRArray

// Len returns the length of an RRArray.
func (array RRArray) Len() int {
	return len(array)
}

// Swap swaps elements on positions i and j from RRArray
func (array RRArray) Swap(i, j int) {
	array[i], array[j] = array[j], array[i]
}

// Less returns true if the element in the position i of RRArray is less than the element in position j of RRArray.
func (array RRArray) Less(i, j int) bool {

	// RR Canonical order:
	// 1.- Canonical Owner Name (RFC 3034 6.1)
	// 2.- RR Class
	// 3.- Type
	// 4.- RRData (as left-aligned canonical form)

	si := dns.SplitDomainName(strings.ToLower(array[i].Header().Name))
	sj := dns.SplitDomainName(strings.ToLower(array[j].Header().Name))

	// Comparing tags, right to left
	ii, ij := len(si)-1, len(sj)-1
	for ii >= 0 && ij >= 0 {
		if si[ii] != sj[ij] {
			return si[ii] < sj[ij]
		}
		ii--
		ij--
	}
	// Now one is a subdomain (or the same domain) of the other
	if ii != ij {
		return ii < ij
	}
	// Equal subdomain
	if array[i].Header().Class != array[j].Header().Class {
		return array[i].Header().Class < array[j].Header().Class
	} else if array[i].Header().Rrtype != array[j].Header().Rrtype {
		return array[i].Header().Rrtype < array[j].Header().Rrtype
	} else {
		return compareRRData(array[i], array[j])
	}

}

// getTypeMap returns an array with the types contained in the array, sorted by value.
func (array RRArray) getTypeMap() map[uint16]bool {
	typeMap := make(map[uint16]bool)
	for _, rr := range array {
		typeMap[rr.Header().Rrtype] = true
	}
	return typeMap
}

// isSignable checks if all the rrs are signable (they should be).
func (array RRArray) isSignable(zone string, nsNames map[string]struct{}) bool {
	for _, rr := range array {
		if !isSignable(rr, zone, nsNames) {
			return false
		}
	}
	return true
}

func compareRRData(rri, rrj dns.RR) bool {
	bytei := make([]byte, dns.MaxMsgSize)
	sizei, err := dns.PackRR(rri, bytei, 0, nil, false)
	if err != nil {
		return false
	}
	rrdatai := bytei[uint16(sizei)-rri.Header().Rdlength : sizei] // We remove the header from the representation
	bytej := make([]byte, dns.MaxMsgSize)
	sizej, err := dns.PackRR(rrj, bytej, 0, nil, false)
	if err != nil {
		return false
	}
	rrdataj := bytej[uint16(sizej)-rrj.Header().Rdlength : sizej] // We remove the header from the representation
	return bytes.Compare(rrdatai, rrdataj) < 0
}

// Len returns the length of an RRSetList.
func (setList RRSetList) Len() int {
	return len(setList)
}

// Swap swaps elements on positions i and j from RRSetList
func (setList RRSetList) Swap(i, j int) {
	setList[i], setList[j] = setList[j], setList[i]
}

// Less returns true if the element in the position i of RRSetList is less than the element in position j of RRSetList.
func (setList RRSetList) Less(i, j int) bool {
	iRRArray := setList[i]
	jRRArray := setList[j]
	if len(iRRArray) == 0 {
		if len(jRRArray) == 0 {
			return false
		}
		return true
	}
	// Create and array to reuse Less method from rrArrays
	cmpArray := append(make(RRArray, 0), iRRArray[0], jRRArray[0])
	return cmpArray.Less(0, 1)
}

// WriteZone prints on writer all the rrs on the array.
// The format of the text printed is the format of a DNS zone.
func (ctx *Context) WriteZone() error {
	if ctx.Output == nil {
		return fmt.Errorf("output not defined in context")
	}
	if _, err := fmt.Fprintln(ctx.Output, ctx.soa); err != nil {
		return err
	}
	for _, rr := range ctx.rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue // Skipping SOA because is the first one
		}
		if _, err := fmt.Fprintln(ctx.Output, rr); err != nil {
			return err
		}
	}
	return nil
}

// getRRSetList groups the rrs by owner name and class if byType is false, or owner name, class and type if byType is true
// NSEC/NSEC3 uses the version with byType = false, and RRSIG uses the other version.
// It assumes the RRArray is properly sorted.
func (ctx *Context) getRRSetList(byType bool) (set RRSetList) {
	// RRsets are RR grouped by rsaLabel and class for NSEC/NSEC3
	// and by rsaLabel, class, type for RRSIG:
	// An RRSIG record contains the signature for an RRset with a particular
	// name, class, and type. RFC4034
	set = make(RRSetList, 0)
	nsNames := getAllNSNames(ctx.rrs)
	var lastRR dns.RR
	for _, rr := range ctx.rrs {
		if isSignable(rr, ctx.Config.Zone, nsNames) {
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
// Finally, it sorts the records
func (ctx *Context) addNSECRecords() {

	set := ctx.getRRSetList(false)

	n := len(set)
	for i, rrs := range set {
		typeMap := make(map[uint16]struct{})
		typeArray := make([]uint16, 0)
		for _, rr := range rrs {
			typeMap[rr.Header().Rrtype] = struct{}{}
		}
		typeMap[dns.TypeNSEC] = struct{}{}

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

		ctx.rrs = append(ctx.rrs, nsec)
	}

	sort.Sort(ctx.rrs)
}

// addNSEC3Records edits an RRArray and adds the respective NSEC3 records to it.
// If optOut is true, it sets the flag for NSEC3PARAM RR, following RFC5155 section 6.
// It returns an error if there is a colission on the hashes.
func (ctx *Context) addNSEC3Records(optOut bool) error {
	setList := ctx.getRRSetList(false)
	salt, err := generateSalt()
	if err != nil {
		return err
	}
	param := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name:   ctx.soa.Hdr.Name,
			Rrtype: dns.TypeNSEC3PARAM,
			Class:  dns.ClassINET,
			Ttl:    ctx.soa.Minttl,
		},
		Hash:       dns.SHA1,
		Iterations: 100, // Is enough
		Salt:       salt,
		SaltLength: uint8(len(salt) / 2),
	}
	if optOut {
		param.Flags = 1
	}

	nsec3List := make([]*dns.NSEC3, 0)

	hashedNames := make(map[string]bool)
	for i, rrSet := range setList {
		typeMap := rrSet.getTypeMap()
		if typeMap[dns.TypeSOA] {
			typeMap[dns.TypeNSEC3PARAM] = true
		}
		if optOut && !typeMap[dns.TypeDS] && !typeMap[dns.TypeDNSKEY] {
			continue
		}
		hName := dns.HashName(rrSet[0].Header().Name, param.Hash,
			param.Iterations, param.Salt)
		if hashedNames[hName] {
			return fmt.Errorf("collision detected")
		}
		hashedNames[hName] = true
		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   hName,
				Rrtype: dns.TypeNSEC3,
				Class:  param.Hdr.Class,
				Ttl:    param.Hdr.Ttl,
			},
			Hash:       param.Hash,
			Flags:      param.Flags,
			Iterations: param.Iterations,
			SaltLength: param.SaltLength,
			Salt:       param.Salt,
			HashLength: 20,
			TypeBitMap: newTypeArray(typeMap),
		}

		if i > 0 { // not the first NSEC3 record
			nsec3List[i-1].NextDomain = nsec3.Hdr.Name
		}
		nsec3List = append(nsec3List, nsec3)
	}
	if len(nsec3List) > 0 {
		// Link the first one
		nsec3List[len(nsec3List)-1].NextDomain = nsec3List[0].Hdr.Name
		for i := 0; i < len(nsec3List); i++ {
			if ctx.Config.Zone != "." {
				nsec3List[i].Header().Name += "." + ctx.Config.Zone
			} else {
				nsec3List[i].Header().Name += ctx.Config.Zone
			}
			ctx.rrs = append(ctx.rrs, nsec3List[i])
		}
	}
	ctx.rrs = append(ctx.rrs, param)
	sort.Sort(ctx.rrs)
	return nil
}

func getAllNSNames(set RRArray) map[string]struct{} {
	m := make(map[string]struct{})
	for _, elem := range set {
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

// sameRRSet returns true if both rrs provided should be on the same RRSetList.
func sameRRSet(rr1, rr2 dns.RR, byType bool) bool {
	if rr1 == nil || rr2 == nil {
		return false
	}
	return rr1.Header().Class == rr2.Header().Class &&
		strings.ToLower(dns.Fqdn(rr1.Header().Name)) == strings.ToLower(dns.Fqdn(rr2.Header().Name)) &&
		(!byType || rr1.Header().Rrtype == rr2.Header().Rrtype)
}

// String returns a string representation of the RRArray, based on the name, class and Rrtype of the first element.
func (array RRArray) String() string {
	if len(array) == 0 {
		return "<empty_setlist>"
	}
	return fmt.Sprintf("%s#%s#%s", array[0].Header().Name, dns.ClassToString[array[0].Header().Class], dns.TypeToString[array[0].Header().Rrtype])
}
