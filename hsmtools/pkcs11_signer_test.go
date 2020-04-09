package hsmtools_test

import (
	"fmt"
	"github.com/niclabs/hsm-tools/hsmtools"
	"strings"
	"testing"
	"time"
)

func TestSession_PKCS11RSASign(t *testing.T) {
	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      false,
			OptOut:     false,
		},
		SignAlgorithm: hsmtools.RSA_SHA256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(key, rsaLabel, p11Lib)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	out, err := sign(t, ctx, session)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := ctx.VerifyFile(); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11RSASignNSEC3(t *testing.T) {
	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     false,
		},
		SignAlgorithm: hsmtools.RSA_SHA256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(key, rsaLabel, p11Lib)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	out, err := sign(t, ctx, session)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := ctx.VerifyFile(); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11RSASignNSEC3OptOut(t *testing.T) {
	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     true,
		},
		SignAlgorithm: hsmtools.RSA_SHA256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(key, rsaLabel, p11Lib)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	out, err := sign(t, ctx, session)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := ctx.VerifyFile(); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ECDSASign(t *testing.T) {
	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      false,
			OptOut:     false,
		},
		SignAlgorithm: hsmtools.ECDSA_P256_SHA256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(key, rsaLabel, p11Lib)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	out, err := sign(t, ctx, session)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := ctx.VerifyFile(); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ECDSASignNSEC3(t *testing.T) {
	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     false,
		},
		SignAlgorithm: hsmtools.ECDSA_P256_SHA256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(key, rsaLabel, p11Lib)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	out, err := sign(t, ctx, session)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := ctx.VerifyFile(); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ECDSASignNSEC3OptOut(t *testing.T) {
	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     true,
		},
		SignAlgorithm: hsmtools.ECDSA_P256_SHA256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(key, rsaLabel, p11Lib)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	out, err := sign(t, ctx, session)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := ctx.VerifyFile(); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ExpiredSig(t *testing.T) {
	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      false,
			OptOut:     false,
		},
		SignAlgorithm: hsmtools.ECDSA_P256_SHA256,
		Log:           Log,
		SignExpDate:   time.Now().AddDate(-1, 0, 0),
	}
	session, err := ctx.NewPKCS11Session(key, rsaLabel, p11Lib)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	out, err := sign(t, ctx, session)
	if err != nil {
		t.Errorf("signing failed: %s", err)
		return
	}
	defer out.Close()
	if err := ctx.VerifyFile(); err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "expired") {
			return
		} else {
			t.Errorf("Expired error expected, but received %s", err)
		}
	} else {
		t.Errorf("Error expected, but nil received")
	}
	return
}
