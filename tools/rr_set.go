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

type NSEC3List struct {
	hashed map[string]string
	rrs    map[string]*dns.NSEC3
}

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

func newNSEC3List() *NSEC3List {
	return &NSEC3List{
		hashed: make(map[string]string),
		rrs:    make(map[string]*dns.NSEC3),
	}
}

func (nsec3Map NSEC3List) toArray() RRArray {
	arr := make(RRArray, 0)
	for _, rr := range nsec3Map.rrs {
		arr = append(arr, rr)
	}
	sort.Sort(arr)
	return arr
}

func (nsec3Map NSEC3List) add(ownerName string, param *dns.NSEC3PARAM, typeMap map[uint16]bool) error {
	hName := dns.HashName(ownerName, param.Hash,
		param.Iterations, param.Salt)
	if hName == "" {
		return fmt.Errorf("empty NSEC3")
	}
	if name, hashedBefore := nsec3Map.hashed[hName]; hashedBefore && ownerName != name {
		return fmt.Errorf("hash collision")
	}
	if nsec3, ok := nsec3Map.rrs[hName]; !ok {
		// It does not exist in the map.
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
		nsec3Map.rrs[hName] = nsec3
	} else {
		// It exists in the map. We need to update it
		subTypeMap := make(map[uint16]bool)
		for k, v := range typeMap {
			subTypeMap[k] = v
		}
		for _, t := range nsec3.TypeBitMap {
			subTypeMap[t] = true
		}
		nsec3.TypeBitMap = newTypeArray(subTypeMap)
	}
	return nil
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
		return len(jRRArray) != 0
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
	var lastRR dns.RR
	for _, rr := range ctx.rrs {
		if ctx.isSignable(rr.Header().Name) {
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
}

// addNSEC3Records edits an RRArray and adds the respective NSEC3 records to it.
// If optOut is true, it sets the flag for NSEC3PARAM RR, following RFC5155 section 6.
// It returns an error if there is a colission on the hashes.
func (ctx *Context) addNSEC3Records() (err error) {
	setList := ctx.getRRSetList(false)
	var salt string
	if ctx.Config.NSEC3SaltValue == "" {
		salt, err = generateSalt(ctx.Config.NSEC3SaltLength)
		if err != nil {
			return err
		}
	} else {
		salt = ctx.Config.NSEC3SaltValue
	}
	param := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name:   ctx.soa.Hdr.Name,
			Rrtype: dns.TypeNSEC3PARAM,
			Class:  dns.ClassINET,
			Ttl:    ctx.soa.Minttl,
		},
		Hash:       dns.SHA1,
		Iterations: ctx.Config.NSEC3Iterations,
		Salt:       salt,
		SaltLength: uint8(len(salt) / 2),
	}
	if ctx.Config.OptOut {
		param.Flags = 1
	}
	nsec3list := newNSEC3List()
	for _, rrSet := range setList {
		typeMap := rrSet.getTypeMap()
		if typeMap[dns.TypeSOA] {
			typeMap[dns.TypeNSEC3PARAM] = true
		}
		// Zones delegated without a DS RR should not have a NSEC3 RR
		_, withDS := ctx.WithDS[rrSet[0].Header().Name]
		_, delegated := ctx.DelegatedZones[rrSet[0].Header().Name]
		if delegated && !withDS && ctx.Config.OptOut {
			continue
		}
		// Add current NSEC3 RR
		err := nsec3list.add(rrSet[0].Header().Name, param, typeMap)
		if err != nil {
			return err
		}
		// Add NSEC3 RRS for each sublabel
		labels := dns.SplitDomainName(strings.TrimSuffix(rrSet[0].Header().Name, ctx.Config.Zone))
		for i := range labels {
			label := strings.Join(labels[i:], ".") + "." + ctx.Config.Zone
			if ctx.isSignable(label) {
				if len(label) == 0 {
					break
				}
				err := nsec3list.add(label, param, typeMap) // we don't know if it is signable
				if err != nil {
					return err
				}
			}
		}
	}
	// transform nsec3list to Sorted RRArray
	sortedList := nsec3list.toArray()
	// Link NSEC3s with their next domains.
	for i, nsec3 := range sortedList {
		nsec3.(*dns.NSEC3).NextDomain = sortedList[(i+1)%len(sortedList)].Header().Name
	}
	// Add zone name to each NSEC3 name.
	for i := 0; i < len(sortedList); i++ {
		sortedList[i].Header().Name += "."
		if ctx.Config.Zone != "." {
			sortedList[i].Header().Name += ctx.Config.Zone
		}
		ctx.rrs = append(ctx.rrs, sortedList[i])
	}
	ctx.rrs = append(ctx.rrs, param)
	return nil
}

// sameRRSet returns true if both rrs provided should be on the same RRSetList.
func sameRRSet(rr1, rr2 dns.RR, byType bool) bool {
	if rr1 == nil || rr2 == nil {
		return false
	}
	return rr1.Header().Class == rr2.Header().Class &&
		strings.EqualFold(dns.Fqdn(rr1.Header().Name), dns.Fqdn(rr2.Header().Name)) &&
		(!byType || rr1.Header().Rrtype == rr2.Header().Rrtype)
}

// String returns a string representation of the RRArray, based on the name, class and Rrtype of the first element.
func (array RRArray) String() string {
	if len(array) == 0 {
		return "<empty_setlist>"
	}
	return fmt.Sprintf("%s#%s#%s", array[0].Header().Name, dns.ClassToString[array[0].Header().Class], dns.TypeToString[array[0].Header().Rrtype])
}
