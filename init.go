package main

import (
	"flag"
	"fmt"
	. "github.com/miekg/pkcs11"
	"os"
)

func init_dHSMsigner() (*Ctx, SessionHandle, string, string, bool, bool, bool) {

	rk := flag.Bool("reset_keys", false, "remove all keys and exit")
	verif := flag.Bool("verify_rrsig", false, "verifies the RRsigs of an already signed zone file and exit")
	ck := flag.Bool("create_keys", false, "create a new pair of keys, outdading all valid keys. Default: first try to find valid keys.")
	zone := flag.String("zone", "", "zone name")
	file := flag.String("file", "", "full path to zone file to be signed or verified")
	p11lib := flag.String("p11lib", "", "full path to pkcs11 lib file")
	nsec3 := flag.Bool("nsec3", false, "Use NSEC3 insted of NSEC (default: NSEC)")
	optout := flag.Bool("opt-out", false, "Use NSEC3 with opt-out")

	flag.Parse()

	if *verif {
		if len(*zone) < 1 || len(*file) < 1 {
			fmt.Fprintf(os.Stderr, "file or zone missing\nUsage of %s:\n", os.Args[0])
			flag.PrintDefaults()
			os.Exit(1)
		}

		_, perr := os.Stat(*file)
		if perr != nil || os.IsNotExist(perr) {
			fmt.Fprintf(os.Stderr, "Error file %s doesn't exists or has not reading permission\n", *file)
			os.Exit(1)
		}
		if err := VerifyFile(*file); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	if len(*p11lib) < 1 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s -p11lib pkcs11_lib --reset_keys\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s -p11lib pkcs11_lib -zone name -file filezon [--create_keys]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}


	if !*rk {
		if len(*zone) < 1 || len(*file) < 1 {
			fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
			flag.PrintDefaults()
			os.Exit(1)
		}

		_, perr := os.Stat(*file)
		if perr != nil || os.IsNotExist(perr) {
			fmt.Fprintf(os.Stderr, "Error file %s doesn't exists or has not reading permission\n", *file)
			os.Exit(1)
		}

	}
	p := New(*p11lib)
	if p == nil {
		fmt.Fprintf(os.Stderr, "Error initializing %s\n", *p11lib)
		panic("File not found")
	}

	err := p.Initialize()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing %s\n", *p11lib)
		fmt.Fprintf(os.Stderr, "Has the .db RW permission?\n")
		panic(err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking slots\n")
		panic(err)
	}

	session, err := p.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating session\n")
		panic(err)
	}

	err = p.Login(session, CKU_USER, "1234")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error login with default key 1234\n")
		panic(err)
	}

	if (*rk) {
		DestroyAllKeys(p, session)
		p.Logout(session)
		p.CloseSession(session)
		p.Finalize()
		p.Destroy()
		fmt.Fprintf(os.Stderr, "All keys destroyed\n")
		os.Exit(1)
	}
	return p, session, *zone, *file, *ck, *nsec3, *optout
}
