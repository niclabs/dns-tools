package tools_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/niclabs/dns-tools/tools"
)

// Using default softHSM configuration. Change it if necessary.
const p11Lib = "/usr/lib/softhsm/libsofthsm2.so" // Path used by Ubuntu Bionic Beaver
const p11Key = "1234"
const p11Label = "hsm"

func TestSession_PKCS11RSASign(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      false,
			OptOut:     false,
		},
		SignAlgorithm: tools.RsaSha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11Label, p11Lib)
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
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     false,
		},
		SignAlgorithm: tools.RsaSha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11Label, p11Lib)
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
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     true,
		},
		SignAlgorithm: tools.RsaSha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11Label, p11Lib)
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
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      false,
			OptOut:     false,
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11Label, p11Lib)
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
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     false,
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11Label, p11Lib)
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
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     true,
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11Label, p11Lib)
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
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:         zone,
			CreateKeys:   true,
			NSEC3:        false,
			OptOut:       false,
			RRSIGExpDate: time.Now().AddDate(-1, 0, 0),
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11Label, p11Lib)
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
