package signer_test

import (
	"github.com/niclabs/hsm-tools/signer"
	"testing"
	"time"
)

func TestSession_PKCS11RSASign(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         false,
			OptOut:        false,
		},
		SignAlgorithm: signer.RSA_SHA256,
		Log: Log,
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
	if err := signer.VerifyFile(zone, "", out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11RSASignNSEC3(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         true,
			OptOut:        false,
		},
		SignAlgorithm: signer.RSA_SHA256,
		Log: Log,
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
	if err := signer.VerifyFile(zone, "", out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11RSASignNSEC3OptOut(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         true,
			OptOut:        true,
		},
		SignAlgorithm: signer.RSA_SHA256,
		Log: Log,
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
	if err := signer.VerifyFile(zone, "", out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ECDSASign(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         false,
			OptOut:        false,
		},
		SignAlgorithm: signer.ECDSA_P256_SHA256,
		Log: Log,
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
	if err := signer.VerifyFile(zone, "", out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ECDSASignNSEC3(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         true,
			OptOut:        false,
		},
		SignAlgorithm: signer.ECDSA_P256_SHA256,
		Log: Log,
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
	if err := signer.VerifyFile(zone, "", out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ECDSASignNSEC3OptOut(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         true,
			OptOut:        true,
		},
		SignAlgorithm: signer.ECDSA_P256_SHA256,
		Log: Log,
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
	if err := signer.VerifyFile(zone, "", out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_PKCS11ExpiredSig(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         false,
			OptOut:        false,
		},
		SignAlgorithm: signer.ECDSA_P256_SHA256,
		Log: Log,
		SignExpDate: time.Now().AddDate(-1, 0, 0),
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
	if err := signer.VerifyFile(zone, "", out, Log); err == nil {
		t.Errorf("output should be alerted as expired, but it was not")
		return
	}
	return
}
