package main

import (
	b64 "encoding/base64"
	"fmt"
	"os"
)

func main() {

	p, session, zone, zfile, create_keys, nsec3, optout := init_dHSMsigner()
	defer p.Destroy()
	defer p.Finalize()
	defer p.CloseSession(session)
	defer p.Logout(session)

	if zone[len(zone)-1] != '.' {
		zone = zone + "."
	}

	rrzone, minTTL := ReadAndParseZone(zfile)

	// bkeys = {pzsk, szsk, pksk, sksk}
	keys, bkeys, expdates := SearchValidKeys(p, session)
	pzsk := keys[0]
	szsk := keys[1]
	pksk := keys[2]
	sksk := keys[3]

	if (create_keys || !bkeys[0] || !bkeys[2]) {

		if create_keys && bkeys[0] {
			ExpireKey(p, session, pzsk)
			ExpireKey(p, session, szsk)
		}
		if create_keys || !bkeys[0] {
			fmt.Fprintf(os.Stderr, "generating zsk\n")
			pzsk, szsk = generateRSAKeyPair(p, session, "zsk", true, 1024)
		}
		if create_keys && bkeys[2] {
			ExpireKey(p, session, pksk)
			ExpireKey(p, session, sksk)
		}
		if create_keys || !bkeys[2] {
			fmt.Fprintf(os.Stderr, "generating ksk\n")
			pksk, sksk = generateRSAKeyPair(p, session, "ksk", true, 2048)
		}
		fmt.Fprintf(os.Stderr, "keys generated\n")
	}

	zsk := CreateNewDNSKEY(
		zone,
		256,
		8,
		minTTL,
		b64.StdEncoding.EncodeToString(GetKeyBytes(p, session, pzsk)),
	)
	ksk := CreateNewDNSKEY(
		zone,
		257,
		8,      // RSASHA256 hardcoded, because I also like to live dangerously
		minTTL,     // SOA -> minimum TTL
		b64.StdEncoding.EncodeToString(GetKeyBytes(p, session, pksk)),
	)

	if (nsec3) {
		AddNSEC3Records(&rrzone, optout)
	} else {
		AddNSECRecords(&rrzone)
	}

	fmt.Fprintf(os.Stderr, "Start signing\n")
	zsksigner := rrSigner{p, session, szsk, pzsk}
	ksksigner := rrSigner{p, session, sksk, pksk}

	rrset := CreateRRset(rrzone, true)

	for _, v := range rrset {
		rrsig := CreateNewRRSIG(zone, zsk, expdates[0], v[0].Header().Ttl)
		err := rrsig.Sign(zsksigner, v)
		if err != nil {
			panic("Error SignRR al firmar")
		}
		err = rrsig.Verify(zsk, v)
		if err != nil {
			panic("Error SignRR en chequeo de firma")
		}
		rrzone = append(rrzone, rrsig)
	}

	rrdnskey := rrArray{zsk, ksk}

	rrdnskeysig := CreateNewRRSIG(zone, ksk, expdates[2], ksk.Hdr.Ttl)
	err := rrdnskeysig.Sign(ksksigner, rrdnskey)
	if err != nil {
		panic("Error SignRR")
	}
	err = rrdnskeysig.Verify(ksk, rrdnskey)
	if err != nil {
		panic(err)
	}

	rrzone = append(rrzone, zsk)
	rrzone = append(rrzone, ksk)
	rrzone = append(rrzone, rrdnskeysig)

	//sort.Sort(rrArray(rrzone))

	fmt.Fprintf(os.Stderr, "DS: %s\n", ksk.ToDS(1)) // SHA256

	PrintZone(rrzone)
	return

}
