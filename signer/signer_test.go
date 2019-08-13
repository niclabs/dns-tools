package signer_test

import (
	"github.com/niclabs/dhsm-signer/signer"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// Using default softHSM configuration. Change it if necessary.
const p11Lib = "/usr/lib/libsofthsm2.so"
const key = "1234"
const label = "dHSM-Test"
const zone = "example.com"
const fileString = `
example.com.	86400	IN	SOA	ns1.example.com. hostmaster.example.com. 2019052103 10800 15 604800 10800
example.com.	86400	IN	NS	ns1.example.com.
example.com.	86400	IN	MX	10 localhost.
ftp.example.com.	86400	IN	CNAME	www.example.com.
ns1.example.com.	86400	IN	A	127.0.0.1
www.example.com.	86400	IN	A	127.0.0.2
yo.example.com.	86400	IN	A	127.0.0.3
`
var Log = log.New(os.Stderr, "[Testing]", log.Ldate|log.Ltime)

func sign(t *testing.T, signArgs *signer.SignArgs) (*os.File, error) {
	session, err := signer.NewSession(p11Lib, key, label, Log)
	reader, writer, err := os.Pipe()

	signArgs.File = strings.NewReader(fileString)
	signArgs.Output = writer

	defer writer.Close()
	if err != nil {
		t.Errorf("Error creating new session: %s", err)
		return nil, err
	}
	session.DestroyAllKeys()

	_, err = session.Sign(signArgs)
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

func TestSession_Sign(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      false,
		OptOut:     false,
	})
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_SignNSEC3(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      true,
		OptOut:     false,
	})
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_SignNSEC3OptOut(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		NSEC3:      true,
		OptOut:     true,
	})
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return
	}
	return
}

func TestSession_ExpiredSig(t *testing.T) {
	out, err := sign(t, &signer.SignArgs{
		Zone:       zone,
		CreateKeys: true,
		SignExpDate: time.Now().AddDate(-1,0,0),
		NSEC3:      false,
		OptOut:     false,
	})
	if err != nil {
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(out, Log); err == nil {
		t.Errorf("output should be alerted as expired, but it was not")
		return
	}
	return
}
