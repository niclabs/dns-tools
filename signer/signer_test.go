package signer_test

import (
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
const rsaLabel = "dHSM-Test"
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

var Log = log.New(os.Stderr, "[Testing] ", log.Ldate|log.Ltime)

func sign(t *testing.T, ctx *signer.Context) (*os.File, error) {

	// Create input and output files
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	ctx.File = strings.NewReader(fileString)
	ctx.Output = writer
	defer writer.Close()

	if err = ctx.ReadAndParseZone(true); err != nil {
		return nil, err
	}
	ctx.AddNSEC13()
	// Session init
	session, err := ctx.NewPKCS11Session(p11Lib)
	defer session.End()
	if err != nil {
		t.Errorf("Error creating new session: %s", err)
		return nil, err
	}
	if ctx.CreateKeys {
		if err = session.DestroyAllKeys(); err != nil {
			t.Errorf("Error destroying old keys: %s", err)
			return nil, err
		}
	}
	_, err = session.Sign()
	if err != nil {
		t.Errorf("Error signing example: %s", err)
		return nil, err
	}
	return reader, nil
}

func TestSession_RSASign(t *testing.T) {
	out, err := sign(t, &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         false,
			OptOut:        false,
			SignAlgorithm: "rsa",
			Key:           key,
			Label:         rsaLabel,
		},
		Log: Log,
	})
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_RSASignNSEC3(t *testing.T) {
	out, err := sign(t, &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    false,
			NSEC3:         true,
			OptOut:        false,
			SignAlgorithm: "rsa",
			Key:           key,
			Label:         rsaLabel,
		},
		Log: Log,
	})
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_RSASignNSEC3OptOut(t *testing.T) {
	out, err := sign(t, &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    false,
			NSEC3:         true,
			OptOut:        true,
			SignAlgorithm: "rsa",
			Key:           key,
			Label:         rsaLabel,
		},
		Log: Log,
	})
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_ECDSASign(t *testing.T) {
	out, err := sign(t, &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         false,
			OptOut:        false,
			SignAlgorithm: "ecdsa",
			Key:           key,
			Label:         rsaLabel,
		},
		Log: Log,
	})
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_ECDSASignNSEC3(t *testing.T) {
	out, err := sign(t, &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    false,
			NSEC3:         true,
			OptOut:        false,
			SignAlgorithm: "ecdsa",
			Key:           key,
			Label:         rsaLabel,
		},
		Log: Log,
	})
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_ECDSASignNSEC3OptOut(t *testing.T) {
	out, err := sign(t, &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    false,
			NSEC3:         true,
			OptOut:        true,
			SignAlgorithm: "ecdsa",
			Key:           key,
			Label:         rsaLabel,
		},
		Log: Log,
	})
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_ExpiredSig(t *testing.T) {
	out, err := sign(t, &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    false,
			NSEC3:         false,
			OptOut:        false,
			SignAlgorithm: "ecdsa",
			Key:           key,
			Label:         rsaLabel,
		},
		Log:         Log,
		SignExpDate: time.Now().AddDate(-1, 0, 0),
	})
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := signer.VerifyFile(zone, out, Log); err == nil {
		t.Errorf("output should be alerted as expired, but it was not")
		return
	}
	return
}
