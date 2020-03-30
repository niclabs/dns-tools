package signer

import (
	"fmt"
	"github.com/miekg/pkcs11"
)

// NewPKCS11Session creates a new session.
// The arguments also define the HSM user key and the rsaLabel the keys will use when created or retrieved.
func (ctx *Context) NewPKCS11Session(p11lib string) (Session, error) {
	p := pkcs11.New(p11lib)
	if p == nil {
		return nil, fmt.Errorf("Error initializing %s: file not found\n", p11lib)
	}
	err := p.Initialize()
	if err != nil {
		return nil, fmt.Errorf("Error initializing %s: %s. (Has the .db RW permission?)\n", p11lib, err)
	}
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("Error checking slots: %s\n", err)
	}
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("Error creating session: %s\n", err)
	}
	err = p.Login(session, pkcs11.CKU_USER, ctx.Key)
	if err != nil {
		return nil, fmt.Errorf("Error login with provided key: %s\n", err)
	}
	algorithm, _ := StringToSignAlgorithm[ctx.SignAlgorithm] // It could be nil
	return &PKCS11Session{
		Context:       ctx,
		P11Context:    p,
		Handle:        session,
		SignAlgorithm: algorithm,
	}, nil
}


// PKCS11Sign signs a zone using the given PKCS11Type library.
func (ctx *Context) PKCS11Sign(p11lib string) (err error) {
	if err = ctx.ReadAndParseZone(true); err != nil {
		return err
	}
	ctx.AddNSEC13()
	session, err := ctx.NewPKCS11Session(p11lib)
	if err != nil {
		return err
	}
	defer session.End()
	/* SIGN MY ANGLE OF MUSIC! */
	if _, err := session.Sign(); err != nil {
		return err
	}
	return nil
}

// PKCS11DestroyKeys destroys the keys from a HSM using the given PKCS11Type library.
func (ctx *Context) PKCS11DestroyKeys(p11lib string) (err error) {
	session, err := ctx.NewPKCS11Session(p11lib)
	if err != nil {
		return err
	}
	defer session.End()
	if err := session.DestroyAllKeys(); err != nil {
		return err
	}
	return nil
}

