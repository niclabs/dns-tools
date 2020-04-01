package signer_test

import (
	"bytes"
	"github.com/niclabs/hsm-tools/signer"
	"testing"
	"time"
)

func TestSession_FileRSASign(t *testing.T) {
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
	zsk := bytes.NewBufferString(RSAZSK)
	ksk := bytes.NewBufferString(RSAKSK)
	session, err := ctx.NewFileSession(zsk, ksk)
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
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_FileRSASignNSEC3(t *testing.T) {
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
	zsk := bytes.NewBufferString(RSAZSK)
	ksk := bytes.NewBufferString(RSAKSK)
	session, err := ctx.NewFileSession(zsk, ksk)
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
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_FileRSASignNSEC3OptOut(t *testing.T) {
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
	zsk := bytes.NewBufferString(RSAZSK)
	ksk := bytes.NewBufferString(RSAKSK)
	session, err := ctx.NewFileSession(zsk, ksk)
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
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_FileECDSASign(t *testing.T) {
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
	zsk := bytes.NewBufferString(ECZSK)
	ksk := bytes.NewBufferString(ECKSK)
	session, err := ctx.NewFileSession(zsk, ksk)
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
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_FileECDSASignNSEC3(t *testing.T) {
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
	zsk := bytes.NewBufferString(ECZSK)
	ksk := bytes.NewBufferString(ECKSK)
	session, err := ctx.NewFileSession(zsk, ksk)
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
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_FileECDSASignNSEC3OptOut(t *testing.T) {
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
	zsk := bytes.NewBufferString(ECZSK)
	ksk := bytes.NewBufferString(ECKSK)
	session, err := ctx.NewFileSession(zsk, ksk)
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
	if err := signer.VerifyFile(zone, out, Log); err != nil {
		t.Errorf("Error verifying output: %s", err)
	}
	return
}

func TestSession_FileExpiredSig(t *testing.T) {
	ctx := &signer.Context{
		ContextConfig: &signer.ContextConfig{
			Zone:          zone,
			CreateKeys:    true,
			NSEC3:         false,
			OptOut:        false,
		},
		Log: Log,
		SignAlgorithm: signer.ECDSA_P256_SHA256,
		SignExpDate: time.Now().AddDate(-1, 0, 0),
	}
	zsk := bytes.NewBufferString(ECZSK)
	ksk := bytes.NewBufferString(ECKSK)
	session, err := ctx.NewFileSession(zsk, ksk)
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
	if err := signer.VerifyFile(zone, out, Log); err == nil {
		t.Errorf("output should be alerted as expired, but it was not")
		return
	}
	return
}
