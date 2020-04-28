package tools_test

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/niclabs/dns-tools/tools"
)

// Using default softHSM configuration. Change it if necessary.
const p11Lib = "/usr/lib/libsofthsm2.so" // Path used by Ubuntu Bionic Beaver
const key = "1234"
const rsaLabel = "hsm"
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

const RSAKSK = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+WJlIsfzzBZ9K
s6A1sTDHUd7jc2a6C7uOBrMHhtsVBTUk96S1CUsnGiT8ZJJwVP+qfHdrQR34IZ9c
HvHipJ+dma0bMdtrLL/mzhrNBuAcVEpCe7i9If/zxpX3UJlijQR5dzf7rrfnEezp
ncOzJ5I0GwmZl3+fomoS72GCxMlNW3LngukOe+3gruAHdQZlDNqELmouUYAcnBSa
xkqqaFrkP0Y87aOf7m2Pl5vdX1gkbpcU5dwwdaawvCzjbxWyrCIL3WskONFL9UY+
3iP0idGHeqSW4bBD1x6UvGsJB0+HmAi0CHQ0bC/2NTYGL4QRzhsY4wHR/+CIx4F+
s8KafyfdAgMBAAECggEAQgmY/IiLuoCb2B3jml0kEDLOQlkaLbe+VTLrz9OwlGVf
H7kvEoPr5+ABLvNxfrlujeZqw/IuhJSdpicyQjBdFB9p2EJ+3nsDBP9CexlEjW+M
5+3mlO+Dzj56bvgujutfvwhmitH+CZPFfvN2HuS+q4cp2HigFXESngkg6m59bHGR
BQDcgNgVwo8wqNr1Y6YivFdO3dxGn5eZqzjzTdGZSksvNqCKr2V+v8IHI4jPz7hs
oLHoqIilLP/NxGQDAZRx67wZwylThjVdVIpb5OuK9Op+wkB1IKu5Gw/BJsmY8IrE
Z/cmRjqlJWAY+qLmP9yKqxq1b6xgncuc+wFcGTaN/QKBgQDvxwSW9431Ni4PLlzB
IzCo6fnFkuOPmrlz0VlC8jRgF6Mdvwy5UslFTF7rI2XZkV6FYIar0LJQuytp9tDI
0Eg4NGNXn5anF9FAXqEsXOkfum813Cjs0GVYRz/HhnZHfx3oe//5vAvMXi4nH+LE
+luRYxWbqTl10o0ocwXlYZxCAwKBgQDLOWwwC40aEJRZGEkfEg8ae13CWh0DqSS9
MhtWwBXnujfpdwZFCi9M1z+X56dVES96dWpr8QDHyEUf980cjaMpcVsYvUnle52A
4jCCdbuPcavbZQOwZiNEUV9z2APpcLqnHj5LafFytvcODuP4RLYwOebtxZVyiPaj
PJXQOQC4nwKBgGKyKNF7VJN6mbrl+ogFVCIzLPyGWeTiazOhGHzV9XkYQawc17/w
s6gyp19iUqobjCyabtSKMtvILzaOwaHnGdMIvVtz9S8SPq+gQ/dexxaoRt6EoNPZ
c93Cdh5K2qTTThxD7jl9jd2xZo30MgOiic5uWpaYMW6uHCxqLCMe6pLBAoGBAJk0
5iHmY2619xCf5Wg+FhLR1GJTyzHaTy8u2jtxPlJfKg2gxKJBxlz4nSGo65aPCSsZ
36wWmY8DpVEvYHtZMBtrMNEayt3tblUesJF5rne6q2QP6FMQ/R9g9UQBIxnW+XBJ
tY7nBLaFxwTbJvQg4PTEghrY7QzWwpFXeF3sy2VjAoGAK4eAUDr8EpGshBcdP0Wc
G2KaieFNatjUJ54YcDXv8cRLVHl8We7GXzjt0mK332wzdb6jI/b18IAubCB9poqc
RkUGNdNXDHXU00dKBoZjiQDYDayoU2cDbEdxhp3mFAVcdmhDuwycVYRiKMuYxsji
NgyBdTRzqMvHz/3MigIE//Q=
-----END PRIVATE KEY-----
`

const RSAZSK = `
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMouLbKrLDPRdfNg
bqYYXXNQEOr8mvfDcQrsjkB23O+CPN9ANUZnj6Y9V5XGiYxUyuVNOGuNv7sLVXOE
0nOtKvP1Lg1js9vJlfYYB3jkdfVOT2S7QdtLxzQLtzOHhLEFXhTMIWI241qXTQ+M
uNqugv2cBEVGYkbkE+vKvwFv3lUjAgMBAAECgYB9IHdHzIheyZOmPFg+k3XCmBrg
U9XU4TBlAmJHo0i5MnFZ+fL+z7knuW8rUuRt5Uxs/Y2dguzWZf1MsTdOQC4EE2+h
qlXj/p5PUW4ivdiceoaTO0+hAJAq/wySTQiHMycKcIaeHJHBYaJ0QuazTDlsUw26
FXAcx1OtHoR8gD49gQJBAPd8FLUGhuGdFQVdfdlCApSe+yIFv+UHj6IwmY6UM7yK
wOth5CdwtzYxQA6/gDkOgaKnk+x/rvq/ocDkGKq8CY8CQQDRIwszbR1vrt6Mxbm7
JnOqOA0VVCo+wCzZeMIA2VY65oe8sHQ+m/RZTvkqY6cWwCuCo84cuWCGKG7iddqA
S2ktAkEAv8A54xDNjR1CXkfT7HOCwFh1yCSgS/oRxd7V+2zEsT7ovve36P8iVTDP
qx2hYZPlyXsB1+oOT2YPE/8nRZIv7QJAIHG2UCESWvwe7GnUOXNqqDKP3Qo0j42S
p54zQpx04yhWUHBzaC8bhitZPjk9d6sSVO8Cj7Q2hDmLkjhEUHjidQJAG+1vLSd0
N81zUl/hrqb5xcxsWWYlzVySdJ8VNkK7Yb6kMTjyrR8cIk59paia/YSbnu2zAMRs
xWPOKbVIW5Dtxg==
-----END PRIVATE KEY-----
`

const ECKSK = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/PlIP7S70tAOWr4c
2jHj86WdoCNuJGBHoBXL70erxVuhRANCAASLhC4FqcsdNLsm/oKtVsiHDx3lAa0o
rHVJ/KFSDgwOPE0XJK4U1/93q/UxBCPc1ptbFjOY+Ki/T6XdRUWFLbxb
-----END PRIVATE KEY-----
`

const ECZSK = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJ7o05fW+9RnEBlzz
D8aiYtF8tpcOCrp/5ofSpBlaVx+hRANCAATwd4+hzR5oFNkZEFC3P/W0oT3RRPk1
1bXj7wN4Rtal/0O+gDJlFhb4B4kiHtD6oS/4nY94neHSUnqaZjuk3q1Z
-----END PRIVATE KEY-----
`

var Log = log.New(os.Stderr, "[Testing] ", log.Ldate|log.Ltime)

func sign(t *testing.T, ctx *tools.Context, session tools.SignSession) (*os.File, error) {

	// Create input and output files
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	ctx.File = bytes.NewBufferString(fileString)
	ctx.Output = writer
	defer writer.Close()
	defer session.End()
	if ctx.Config.CreateKeys {
		if err = session.DestroyAllKeys(); err != nil {
			t.Errorf("Error destroying old keys: %s", err)
			return nil, err
		}
	}
	_, err = tools.Sign(session)
	if err != nil {
		t.Errorf("Error signing example: %s", err)
		return nil, err
	}
	return reader, nil
}

func TestContext_ReadAndParseZone(t *testing.T) {
	ctx := tools.Context{
		Config: &tools.ContextConfig{
			Zone: "wrong.zone",
		},
		File: bytes.NewBufferString(fileString),
		Log:  Log,
	}
	err := ctx.ReadAndParseZone(false)
	if err != nil {
		t.Errorf("%s", err)
	}
}
