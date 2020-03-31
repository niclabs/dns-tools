package signer

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
	"io"
	"log"
	"os"
	"sort"
	"time"
)

// Context contains the state of a zone signing process.
type Context struct {
	*ContextConfig
	SignExpDate time.Time      // Expiration date for the signature.
	File        io.Reader      // sessionType path
	Output      io.WriteCloser // Out path
	RRs         RRArray        // RRs
	Log         *log.Logger    // Logger
}

// ContextConfig contains the common args to sign and verify files
type ContextConfig struct {
	Zone          string // Zone name
	CreateKeys    bool   // If True, the sign process creates new keys for the signature.
	NSEC3         bool   // If true, the zone is signed using NSEC3
	OptOut        bool   // If true and NSEC3 is true, the zone is signed using OptOut NSEC3 flag.
	MinTTL        uint32 // Min TTL ;-)
	Label         string // Signature Label
	SignAlgorithm string // Signature algorithm
	Key           string // Signature key
	ExpDateStr    string // Expiration Date in String
	FilePath      string // Output Path
	OutputPath    string // Output Path
}

// NewContext creates a new context based on a configuration structure. It also receives
// a logger to log errors.
func NewContext(config *ContextConfig, log *log.Logger) (ctx *Context, err error) {

	ctx = &Context{
		ContextConfig: config,
		Log:           log,
		SignExpDate:   time.Now().AddDate(1, 0, 0),
		Output:        os.Stdout,
	}

	if len(config.FilePath) > 0 {
		ctx.File, err = os.Open(config.FilePath)
		if err != nil {
			return nil, err
		}
	}

	if len(config.ExpDateStr) > 0 {
		parsedDate, err := time.Parse("20060102", config.ExpDateStr)
		if err != nil {
			return nil, fmt.Errorf("cannot parse expiration date: %s", err)
		}
		ctx.SignExpDate = parsedDate
	}

	if len(config.OutputPath) > 0 {
		writer, err := os.Create(config.OutputPath)
		if err != nil {
			return nil, fmt.Errorf("couldn't create out file in path %s: %s", config.OutputPath, err)
		}
		ctx.Output = writer
	}
	return ctx, nil
}

// ReadAndParseZone parses a DNS zone file and returns an array of RRs and the zone minTTL.
// It also updates the serial in the SOA record if updateSerial is true.
func (ctx *Context) ReadAndParseZone(updateSerial bool) error {

	if ctx.File == nil {
		return fmt.Errorf("no file defined on context")
	}

	rrs := make(RRArray, 0)

	if ctx.Zone[len(ctx.Zone)-1] != '.' {
		ctx.Zone = ctx.Zone + "."
	}

	zone := dns.NewZoneParser(ctx.File, "", "")
	if err := zone.Err(); err != nil {
		return err
	}
	for rr, ok := zone.Next(); ok; rr, ok = zone.Next() {
		rrs = append(rrs, rr)
		if rr.Header().Rrtype == dns.TypeSOA {
			var soa *dns.SOA
			soa = rr.(*dns.SOA)
			ctx.MinTTL = soa.Minttl
			// UPDATING THE SERIAL
			if updateSerial {
				rr.(*dns.SOA).Serial += 2
			}
		}
	}
	sort.Sort(rrs)
	ctx.RRs = rrs
	return nil
}

// AddNSEC13 adds NSEC 1 and 3 RRs to the RR list.
func (ctx *Context) AddNSEC13() {
	if ctx.NSEC3 {
		for {
			if err := ctx.RRs.addNSEC3Records(ctx.Zone, ctx.OptOut); err == nil {
				break
			}
		}
	} else {
		ctx.RRs.addNSECRecords(ctx.Zone)
	}
}

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
		ctx:           ctx,
		P11Context:    p,
		Handle:        session,
		SignAlgorithm: algorithm,
	}, nil
}

// NewFileSession creates a new File session.
// The arguments define the readers for the zone signing and key signing keys.
func (ctx *Context) NewFileSession(zsk, ksk io.Reader) (Session, error) {
	return nil, nil
}

// Close closes the output file if it is defined.
func (ctx *Context) Close() error {
	if ctx.Output != nil {
		err := ctx.Output.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
