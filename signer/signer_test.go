package signer_test

import (
	"github.com/niclabs/dhsm-signer/signer"
	"io"
	"log"
	"os"
	"strings"
	"testing"
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

func sign(t *testing.T, nsec3, optOut bool) (*os.File, error) {
	session, err := signer.NewSession(p11Lib, key, label, Log)
	reader, writer, err := os.Pipe()
	defer writer.Close()
	if err != nil {
		t.Errorf("Error creating new session: %s", err)
		return nil, err
	}
	session.DestroyAllKeys()
	file:= strings.NewReader(fileString)

	_, err = session.Sign(&signer.SignArgs{
		Zone:       zone,
		File:       file,
		CreateKeys: true,
		NSEC3:      nsec3,
		OptOut:     optOut,
		Output:     writer,
	})
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

func verify(t *testing.T, out io.Reader) error {
	if err := signer.VerifyFile(out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
		return err
	}
	return nil
}

func TestSession_Sign(t *testing.T) {
	out, err := sign(t, false, false)
	if err != nil {
		return
	}
	defer out.Close()
	verify(t, out)
}

func TestSession_SignNSEC3(t *testing.T) {
	out, err := sign(t, true, false)
	if err != nil {
		return
	}
	defer out.Close()
	verify(t, out)
}

func TestSession_SignNSEC3OptOut(t *testing.T) {
	out, err := sign(t, true, true)
	if err != nil {
		return
	}
	defer out.Close()
	verify(t, out)
}
