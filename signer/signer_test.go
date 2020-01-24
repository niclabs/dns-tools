package signer_test

import (
	"github.com/miekg/dns"
	"github.com/niclabs/hsm-tools/signer"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// Using default softHSM configuration. Change it if necessary.
const p11Lib = "/home/eriveros/go/src/dtc/dtc.so"
const key = "1234"
const label = "dHSM-Test"
const zone = "example.com."
const fileString = `
example.com.			86400	IN	SOA		ns1.example.com. hostmaster.example.com. 2019052103 10800 15 604800 10800
delegate.example.com. 	86400 	IN 	NS 		other.domain.com.
delegate.example.com. 	86400 	IN 	A 		127.0.0.4
example.com.			86400	IN	NS		ns1.example.com.
example.com.			86400	IN	MX	10 	localhost.
ftp.example.com.		86400	IN	CNAME	www.example.com.
ns1.example.com.		86400	IN	A		127.0.0.1
www.example.com.		86400	IN	A		127.0.0.2
yo.example.com.			86400	IN	A		127.0.0.3
`

var Log = log.New(os.Stderr, "[Testing]", log.Ldate|log.Ltime)

func sign(t *testing.T, signArgs *signer.SignArgs, algorithm string) (*os.File, error) {
	session, err := signer.NewSession(p11Lib, key, label, algorithm, Log)
	if err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	signArgs.File = strings.NewReader(fileString)
	signArgs.Output = writer

	defer writer.Close()
	if err != nil {
		t.Errorf("Error creating new session: %s", err)
		return nil, err
	}
	_ = session.DestroyAllKeys()
	args := &signer.SessionSignArgs{SignArgs: signArgs}
	if err := session.GetKeys(args); err != nil {
		t.Errorf("error getting keys: %s", err)
		return nil, err
	}
	_, err = session.Sign(args)
	if err != nil {
		t.Errorf("Error signing example: %s", err)
		return nil, err
	}
	if err := session.End(); err != nil {
		t.Errorf("Error ending session: %s", err)
		return nil, err
	}
	return reader, nil
}

func TestSession_SignRSA(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      false,
		OptOut:     false,
	}, "rsa")
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_SignRSANSEC3(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      true,
		OptOut:     false,
	}, "rsa")
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_SignRSANSEC3OptOut(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      true,
		OptOut:     true,
	}, "rsa")
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_SignECDSA(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      false,
		OptOut:     false,
	}, "ecdsa")
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_SignECDSANSEC3(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      true,
		OptOut:     false,
	}, "ecdsa")
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_SignECDSANSEC3OptOut(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      true,
		OptOut:     true,
	}, "ecdsa")
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_ExpiredSig(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:        zone,
		CreateKeys:  true,
		SignExpDate: time.Now().AddDate(-1, 0, 0),
		NSEC3:       false,
		OptOut:      false,
	}, "rsa")
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err == nil {
		t.Errorf("output should be alerted as expired, but it was not")
		return
	}
	return
}

func TestSession_NoDelegation(t *testing.T) {
	args := &signer.SignArgs{
		Zone:        zone,
		CreateKeys:  true,
		SignExpDate: time.Now().AddDate(-1, 0, 0),
		NSEC3:       false,
		OptOut:      false,
	}
	out, err := sign(t, args, "rsa")
	if err != nil {
		return
	}
	defer out.Close()
	rrZone, err := signer.ReadAndParseZone(args, false)

	for _, rr := range rrZone {
		_, isNSEC := rr.(*dns.NSEC)
		_, isNSEC3 := rr.(*dns.NSEC3)
		_, isRRSIG := rr.(*dns.RRSIG)
		if strings.Contains(rr.Header().Name, "delegate") && (isNSEC || isNSEC3 || isRRSIG) {
			t.Errorf("NS Delegation or Glue Record was signed: %s", rr)
		}
	}

	return
}
