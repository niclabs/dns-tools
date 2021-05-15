package tools_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/niclabs/dns-tools/tools"
)

func TestSession_PKCS11RSASign(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      false,
			OptOut:     false,
			VerifyThreshold: time.Now(),
		},
		SignAlgorithm: tools.RsaSha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11LabelRSA, p11Lib)
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
}

func TestSession_PKCS11RSASignNSEC3(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     false,
			VerifyThreshold: time.Now(),
		},
		SignAlgorithm: tools.RsaSha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11LabelRSA, p11Lib)
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
}

func TestSession_PKCS11RSASignNSEC3OptOut(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     true,
			VerifyThreshold: time.Now(),
		},
		SignAlgorithm: tools.RsaSha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11LabelRSA, p11Lib)
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
}

func TestSession_PKCS11ECDSASign(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      false,
			OptOut:     false,
			VerifyThreshold: time.Now(),
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11LabelECDSA, p11Lib)
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
}

func TestSession_PKCS11ECDSASignNSEC3(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:       zone,
			CreateKeys: true,
			NSEC3:      true,
			OptOut:     false,
			VerifyThreshold: time.Now(),
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11LabelECDSA, p11Lib)
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
}

func TestSession_PKCS11ECDSASignNSEC3OptOut(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:            zone,
			CreateKeys:      true,
			NSEC3:           true,
			OptOut:          true,
			VerifyThreshold: time.Now(),
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11LabelECDSA, p11Lib)
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
}

func TestSession_PKCS11ExpiredSig(t *testing.T) {
	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:            zone,
			CreateKeys:      true,
			NSEC3:           false,
			OptOut:          false,
			RRSIGExpDate:    time.Now().AddDate(-1, 0, 0),
			VerifyThreshold: time.Now(),
		},
		SignAlgorithm: tools.EcdsaP256Sha256,
		Log:           Log,
	}
	session, err := ctx.NewPKCS11Session(p11Key, p11LabelECDSA, p11Lib)
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
}
