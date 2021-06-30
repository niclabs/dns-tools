package tools_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/niclabs/dns-tools/tools"
)

const simpleZone = `
example.      86400   IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
			  86400   IN  NS      ns1
			  86400   IN  NS      ns2
			  86400   IN  ZONEMD  2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c
ns1           3600    IN  A       203.0.113.63
ns2           3600    IN  AAAA    2001:db8::63
`

const complexZone = `
example.		86400   IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
				86400   IN  NS      ns1
				86400   IN  NS      ns2
				86400   IN  ZONEMD  2018031900 1 1 31cefb03814f5062ad12fa951ba0ef5f8da6ae354a415767246f7dc932ceb1e742a2108f529db6a33a11c01493de358d
ns1				3600    IN  A       203.0.113.63
ns2				3600    IN  AAAA    2001:db8::63
occluded.sub	7200    IN  TXT     "I'm occluded but must be digested"
sub				7200    IN  NS      ns1
duplicate		300     IN  TXT     "I must be digested just once"
duplicate		300     IN  TXT     "I must be digested just once"
foo.test.		555     IN  TXT     "out-of-zone data must be excluded"
non-apex 		900     IN  ZONEMD  2018031900 1 1 616c6c6f776564206275742069676e6f7265642e20616c6c6f776564206275742069676e6f7265642e20616c6c6f7765`

const signedZone = `
uri.arpa.         3600    IN      SOA     sns.dns.icann.org. noc.dns.icann.org. 2018100702 10800 3600 1209600 3600 
uri.arpa.         3600    IN      RRSIG   NSEC 8 2 3600 20181028142623 20181007205525 47155 uri.arpa. eEC4w/oXLR1Epwgv4MBiDtSBsXhqrJVvJWUpbX8XpetAvD35bxwNCUTi/pAJVUXefegWeiriD2rkTgCBCMmn7YQIm3gdR+HjY/+o3BXNQnz97f+eHAE9EDDzoNVfL1PyV/2fde9tDeUuAGVVwmD399NGq9jWYMRpyri2kysr q/g=
uri.arpa.         86400   IN      RRSIG   NS 8 2 86400 20181028172020 20181007175821 47155 uri.arpa. ATyV2A2A8ZoggC+68u4GuP5MOUuR+2rr3eWOkEU55zAHld/7FiBxl4ln4byJYy7NudUwlMOEXajqFZE7DVl8PpcvrP3HeeGaVzKqaWj+aus0jbKFBsvs2b1qDZemBfkz/IfAhUTJKnto0vSUicJKfItu0GjyYNJCz2CqEuGD Wxc= 
uri.arpa.         600     IN      RRSIG   MX 8 2 600 20181028170556 20181007175821 47155 uri.arpa. e7/r3KXDohX1lyVavetFFObp8fB8aXT76HnN9KCQDxSnSghNM83UQV0tlTtD8JVeN1mCvcNFZpagwIgB7XhTtm6Beur/m5ES+4uSnVeS6Q66HBZKA3mR95IpevuVIZvvJ+GcCAQpBo6KRODYvJ/c/ZG6sfYWkZ7qg/Em5/+3 4UI=
uri.arpa.         3600    IN      RRSIG   DNSKEY 8 2 3600 20181028152832 20181007175821 15796 uri.arpa. nzpbnh0OqsgBBP8St28pLvPEQ3wZAUdEBuUwil+rtjjWlYYiqjPxZ286XF4Rq1usfV5x71jZz5IqswOaQgia91ylodFpLuXD6FTGs2nXGhNKkg1VchHgtwj70mXU72GefVgo8TxrFYzxuEFP5ZTP92t97FVWVVyyFd86sbbR6DZj3uA2wEvqBVLECgJLrMQ9Yy7MueJl3UA4h4E6zO2JY9Yp0W9woq0BdqkkwYTwzogyYffPmGAJG91RJ2h6cHtFjEZe2MnaY2glqniZ0WT9vXXduFPm0KD9U77Ac+ZtctAF9tsZwSdAoL365E2L1usZbA+K0BnPPqGFJRJk5R0A1w==
uri.arpa.         3600    IN      RRSIG   DNSKEY 8 2 3600 20181028152832 20181007175821 55480 uri.arpa. lWtQV/5szQjkXmbcD47/+rOW8kJPksRFHlzxxmzt906+DBYyfrH6uq5XnHvrUlQO6M12uhqDeL+bDFVgqSpNy+42/OaZvaK3J8EzPZVBHPJykKMV63T83aAiJrAyHzOaEdmzLCpalqcEE2ImzlLHSafManRfJL8Yuv+JDZFj2WDWfEcUuwkmIZWX11zxp+DxwzyUlRl7x4+ok5iKZWIg5UnBAf6B8T75WnXzlhCw3F2pXI0a5LYg71L3Tp/xhjN6Yy9jGlIRf5BjB59X2zra3a2RPkI09SSnuEwHyF1mDaV5BmQrLGRnCjvwXA7ho2m+vv4SP5dUdXf+GTeA1HeBfw== 
uri.arpa.         3600    IN      RRSIG   SOA 8 2 3600 20181029114753 20181008222815 47155 uri.arpa. qn8yBNoHDjGdT79U2Wu9IIahoS0YPOgYP8lG+qwPcrZ1BwGiHywuoUa2Mx6BWZlg+HDyaxj2iOmox+IIqoUHhXUbO7IUkJFlgrOKCgAR2twDHrXu9BUQHy9SoV16wYm3kBTEPyxW5FFm8vcdnKAF7sxSY8BbaYNpRIEjDx4A JUc= 
uri.arpa.         3600    IN      NSEC    ftp.uri.arpa. NS SOA MX RRSIG NSEC DNSKEY 
uri.arpa.         86400   IN      NS      a.iana-servers.net.
uri.arpa.         86400   IN      NS      b.iana-servers.net.
uri.arpa.         86400   IN      NS      c.iana-servers.net.
uri.arpa.         86400   IN      NS      ns2.lacnic.net.
uri.arpa.         86400   IN      NS      sec3.apnic.net.
uri.arpa.         600     IN      MX      10 pechora.icann.org.
uri.arpa.         3600    IN      DNSKEY  256 3 8 AwEAAcBi7tSart2J599zbYWspMNGN70IBWb4ziqyQYH9MTB/VCz6WyUKuXunwiJJbbQ3bcLqTLWEw134B6cTMHrZpjTAb5WAwg4XcWUu8mdcPTiLBl6qVRlRD0WiFCTzuYUfkwsh1Rbr7rvrxSQhF5rh71zSpwV5jjjp65WxSdJjlH0B 
uri.arpa.         3600    IN      DNSKEY  257 3 8 AwEAAbNVv6ulgRdO31MtAehz7j3ALRjwZglWesnzvllQl/+hBRZr9QoYcO2I+DkO4Q1NKxox4DUIxj8SxPO3GwDuOFR9q2/CFi2O0mZjafbdYtWc3zSdBbi3q0cwCIx7GuG9eqlL+pg7mdk9dgdNZfHwB0LnqTD8ebLPsrO/Id7kBaiqYOfMlZnh2fp+2h6OOJZHtY0DK1UlssyB5PKsE0tVzo5s6zo9iXKe5u+8WTMaGDY49vG80JPAKE7ezMiH/NZcUMiE0PRZ8D3foq2dYuS5ym+vA83Z7v8A+Rwh4UGnjxKB8zmr803V0ASAmHz/gwH5Vb0nH+LObwFtl3wpbp+Wpm8= 
uri.arpa.         3600    IN      DNSKEY  257 3 8 AwEAAbwnFTakCvaUKsXji4mgmxZUJi1IygbnGahbkmFEa0L16J+TchKRwcgzVfsxUGa2MmeA4hgkAooC3uy+tTmoMsgy8uq/JAj24DjiHzd46LfDFK/qMidVqFpYSHeq2Vv5ojkuIsx4oe4KsafGWYNOczKZgH5loGjN2aJGmrIm++XCphOskgCsQYl65MIzuXffzJyxlAuts+ecAIiVeqRaqQfr8LRU7wIsLxinXirprtQrbor+EtvlHp9qXE6ARTZDzf4jvsNpKvLFZtmxzFf3e/UJz5eHjpwDSiZL7xE8aE1o1nGfPtJx9ZnB3bapltaJ5wY+5XOCKgY0xmJVvNQlwdE= 
ftp.uri.arpa.     3600    IN      RRSIG   NSEC 8 3 3600 20181028080856 20181007175821 47155 uri.arpa. HClGAqPxzkYkAT7Q/QNtQeB6YrkP6EPOef+9Qo5/2zngwAewXEAQiyF9jD1USJiroM11QqBS3v3aIdW/LXORs4Ez3hLcKNO1cKHsOuWAqzmE+BPPArfh8N95jqh/q6vpaB9UtMkQ53tM2fYU1GszOLN0knxbHgDHAh2axMGH lqM= 
ftp.uri.arpa.     604800  IN      RRSIG   NAPTR 8 3 604800 20181028103644 20181007205525 47155 uri.arpa. WoLi+vZzkxaoLr2IGZnwkRvcDf6KxiWQd1WZP/U+AWnV+7MiqsWPZaf09toRErerGoFOiOASNxZjBGJrRgjmavOM9U+LZSconP9zrNFd4dIu6kp5YxlQJ0uHOvx1ZHFCj6lAt1ACUIw04ZhMydTmi27c8MzEOMepvn7iH7r7 k7k= 
ftp.uri.arpa.     3600    IN      NSEC    http.uri.arpa. NAPTR RRSIG NSEC
ftp.uri.arpa.     604800  IN      NAPTR   0 0 "" "" "!^ftp://([^:/?#]*).*$!\\1!i" . 
http.uri.arpa.    3600    IN      RRSIG   NSEC 8 3 3600 20181029010647 20181007175821 47155 uri.arpa. U03NntQ73LHWpfLmUK8nMsqkwVsOGW2KdsyuHYAjqQSZvKbtmbv7HBmEH1+Ii3Z+wtfdMZBy5aC/6sHdx69BfZJs16xumycMlAy6325DKTQbIMN+ift9GrKBC7cgCd2msF/uzSrYxxg4MJQzBPvlkwXnY3b7eJSlIXisBIn7 3b8= 
http.uri.arpa.    604800  IN      RRSIG   NAPTR 8 3 604800 20181029011815 20181007205525 47155 uri.arpa. T7mRrdag+WSmG+n22mtBSQ/0Y3v+rdDnfQV90LN5Fq32N5K2iYFajF7FTp56oOznytfcL4fHrqOE0wRc9NWOCCUec9C7Wa1gJQcllEvgoAM+L6f0RsEjWq6+9jvlLKMXQv0xQuMX17338uoD/xiAFQSnDbiQKxwWMqVAimv5 7Zs= 
http.uri.arpa.    3600    IN      NSEC    mailto.uri.arpa. NAPTR RRSIG NSEC 
http.uri.arpa.    604800  IN      NAPTR   0 0 "" "" "!^http://([^:/?#]*).*$!\\1!i" . 
mailto.uri.arpa.  3600    IN      RRSIG   NSEC 8 3 3600 20181028110727 20181007175821 47155 uri.arpa. GvxzVL85rEukwGqtuLxek9ipwjBMfTOFIEyJ7afC8HxVMs6mfFa/nEM/IdFvvFg+lcYoJSQYuSAVYFl3xPbgrxVSLK125QutCFMdC/YjuZEnq5clfQciMRD7R3+znZfm8d8u/snLV9w4D+lTBZrJJUBe1Efc8vum5vvV7819 ZoY= 
mailto.uri.arpa.  604800  IN      RRSIG   NAPTR 8 3 604800 20181028141825 20181007205525 47155 uri.arpa. MaADUgc3fc5v++M0YmqjGk3jBdfIA5RuP62hUSlPsFZO4k37erjIGCfFj+g84yc+QgbSde0PQHszl9fE/+SU5ZXiS9YdcbzSZxp2erFpZOTchrpg916T4vx6i59scodjb0l6bDyZ+mtIPrc1w6b4hUyOUTsDQoAJYxdfEuMg Vy4= 
mailto.uri.arpa.  3600    IN      NSEC    urn.uri.arpa. NAPTR RRSIG NSEC 
mailto.uri.arpa.  604800  IN      NAPTR   0 0 "" "" "!^mailto:(.*)@(.*)$!\\2!i" . 
urn.uri.arpa.     3600    IN      RRSIG   NSEC 8 3 3600 20181028123243 20181007175821 47155 uri.arpa. Hgsw4Deops1O8uWyELGe6hpR/OEqCnTHvahlwiQkHhO5CSEQrbhmFAWeUOkmGAdTEYrSz+skLRQuITRMwzyFf4oUkZihGyhZyzHbcxWfuDc/Pd/9DSl56gdeBwy1evn5wBTms8yWQVkNtphbJH395gRqZuaJs3LD/qTyJ5Dp LvA=
urn.uri.arpa.     604800  IN      RRSIG   NAPTR 8 3 604800 20181029071816 20181007205525 47155 uri.arpa. ALIZD0vBqAQQt40GQ0Efaj8OCyE9xSRJRdyvyn/H/wZVXFRFKrQYrLASD/K7q6CMTOxTRCu2J8yes63WJiaJEdnh+dscXzZkmOg4n5PsgZbkvUSWBiGtxvz5jNncM0xVbkjbtByrvJQAO1cU1mnlDKe1FmVB1uLpVdA9Ib4J hMU= 
urn.uri.arpa.     3600    IN      NSEC    uri.arpa. NAPTR RRSIG NSEC 
urn.uri.arpa.     604800  IN      NAPTR   0 0 "" "" "/urn:([^:]+)/\\1/i" . 
uri.arpa.       3600    IN      ZONEMD  2018100702 1 1 1291b78ddf7669b1a39d014d87626b709b55774c5d7d58fadc556439889a10eaf6f11d615900a4f996bd46279514e473 
`

const rootServers = `
root-servers.net.     3600000 IN  SOA     a.root-servers.net. nstld.verisign-grs.com. 2018091100 14400 7200 1209600 3600000
root-servers.net.     3600000 IN  NS      a.root-servers.net.
root-servers.net.     3600000 IN  NS      b.root-servers.net.
root-servers.net.     3600000 IN  NS      c.root-servers.net.
root-servers.net.     3600000 IN  NS      d.root-servers.net.
root-servers.net.     3600000 IN  NS      e.root-servers.net.
root-servers.net.     3600000 IN  NS      f.root-servers.net.
root-servers.net.     3600000 IN  NS      g.root-servers.net.
root-servers.net.     3600000 IN  NS      h.root-servers.net.
root-servers.net.     3600000 IN  NS      i.root-servers.net.
root-servers.net.     3600000 IN  NS      j.root-servers.net.
root-servers.net.     3600000 IN  NS      k.root-servers.net.
root-servers.net.     3600000 IN  NS      l.root-servers.net.
root-servers.net.     3600000 IN  NS      m.root-servers.net.
a.root-servers.net.   3600000 IN  AAAA    2001:503:ba3e::2:30
a.root-servers.net.   3600000 IN  A       198.41.0.4
b.root-servers.net.   3600000 IN  MX      20 mail.isi.edu.
b.root-servers.net.   3600000 IN  AAAA    2001:500:200::b
b.root-servers.net.   3600000 IN  A       199.9.14.201
c.root-servers.net.   3600000 IN  AAAA    2001:500:2::c
c.root-servers.net.   3600000 IN  A       192.33.4.12
d.root-servers.net.   3600000 IN  AAAA    2001:500:2d::d
d.root-servers.net.   3600000 IN  A       199.7.91.13
e.root-servers.net.   3600000 IN  AAAA    2001:500:a8::e
e.root-servers.net.   3600000 IN  A       192.203.230.10
f.root-servers.net.   3600000 IN  AAAA    2001:500:2f::f
f.root-servers.net.   3600000 IN  A       192.5.5.241
g.root-servers.net.   3600000 IN  AAAA    2001:500:12::d0d
g.root-servers.net.   3600000 IN  A       192.112.36.4
h.root-servers.net.   3600000 IN  AAAA    2001:500:1::53
h.root-servers.net.   3600000 IN  A       198.97.190.53
i.root-servers.net.   3600000 IN  MX      10 mx.i.root-servers.org.
i.root-servers.net.   3600000 IN  AAAA    2001:7fe::53
i.root-servers.net.   3600000 IN  A       192.36.148.17
j.root-servers.net.   3600000 IN  AAAA    2001:503:c27::2:30
j.root-servers.net.   3600000 IN  A       192.58.128.30
k.root-servers.net.   3600000 IN  AAAA    2001:7fd::1
k.root-servers.net.   3600000 IN  A       193.0.14.129
l.root-servers.net.   3600000 IN  AAAA    2001:500:9f::42
l.root-servers.net.   3600000 IN  A       199.7.83.42
m.root-servers.net.   3600000 IN  AAAA    2001:dc3::35
m.root-servers.net.   3600000 IN  A       202.12.27.33
root-servers.net.     3600000 IN  ZONEMD  2018091100 1 1 f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a978a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79
`

const wrongRootServers = `
root-servers.net.     3600000 IN  SOA     a.root-servers.net. nstld.verisign-grs.com. 2018091100 14400 7200 1209600 3600000
root-servers.net.     3600000 IN  NS      a.root-servers.net.
root-servers.net.     3600000 IN  NS      b.root-servers.net.
root-servers.net.     3600000 IN  NS      c.root-servers.net.
root-servers.net.     3600000 IN  NS      d.root-servers.net.
root-servers.net.     3600000 IN  NS      e.root-servers.net.
root-servers.net.     3600000 IN  NS      f.root-servers.net.
root-servers.net.     3600000 IN  NS      g.root-servers.net.
root-servers.net.     3600000 IN  NS      h.root-servers.net.
root-servers.net.     3600000 IN  NS      i.root-servers.net.
root-servers.net.     3600000 IN  NS      j.root-servers.net.
root-servers.net.     3600000 IN  NS      k.root-servers.net.
root-servers.net.     3600000 IN  NS      l.root-servers.net.
root-servers.net.     3600000 IN  NS      m.root-servers.net.
a.root-servers.net.   3600000 IN  AAAA    2001:503:ba3e::2:30
a.root-servers.net.   3600000 IN  A       198.41.0.4
b.root-servers.net.   3600000 IN  MX      20 mail.isi.edu.
b.root-servers.net.   3600000 IN  AAAA    2001:500:200::b
b.root-servers.net.   3600000 IN  A       199.9.14.201
c.root-servers.net.   3600000 IN  AAAA    2001:500:2::c
c.root-servers.net.   3600000 IN  A       192.33.4.12
d.root-servers.net.   3600000 IN  AAAA    2001:500:2d::d
d.root-servers.net.   3600000 IN  A       199.7.91.13
e.root-servers.net.   3600000 IN  AAAA    2001:500:a8::e
e.root-servers.net.   3600000 IN  A       192.203.230.10
f.root-servers.net.   3600000 IN  AAAA    2001:500:2f::f
f.root-servers.net.   3600000 IN  A       192.5.5.241
g.root-servers.net.   3600000 IN  AAAA    2001:500:12::d0d
g.root-servers.net.   3600000 IN  A       192.112.36.4
h.root-servers.net.   3600000 IN  AAAA    2001:500:1::53
h.root-servers.net.   3600000 IN  A       198.97.190.53
i.root-servers.net.   3600000 IN  MX      10 mx.i.root-servers.org.
i.root-servers.net.   3600000 IN  AAAA    2001:7fe::53
i.root-servers.net.   3600000 IN  A       192.36.148.17
j.root-servers.net.   3600000 IN  AAAA    2001:503:c27::2:30
j.root-servers.net.   3600000 IN  A       192.58.128.30
k.root-servers.net.   3600000 IN  AAAA    2001:7fd::1
k.root-servers.net.   3600000 IN  A       193.0.14.129
l.root-servers.net.   3600000 IN  AAAA    2001:500:9f::42
l.root-servers.net.   3600000 IN  A       199.7.83.42
m.root-servers.net.   3600000 IN  AAAA    2001:dc3::35
m.root-servers.net.   3600000 IN  A       202.12.27.33
root-servers.net.     3600000 IN  SOA     a.root-servers.net. nstld.verisign-grs.com. 2018091100 14400 7200 1209600 3600000
root-servers.net.     3600000 IN  ZONEMD  2018091100 1 1 f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a978a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f78` // <- the last character should have been 9

const multiZONEMDZone = `
example.      86400   IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
example.      86400   IN  NS      ns1.example.
example.      86400   IN  NS      ns2.example.
example.      86400   IN  ZONEMD  2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306 
example.      86400   IN  ZONEMD  2018031900 1 240 e2d523f654b9422a96c5a8f44607bbee 
example.      86400   IN  ZONEMD  2018031900 241 1 e1846540e33a9e4189792d18d5d131f605fc283e 
ns1.example.  3600    IN  A       203.0.113.63
ns2.example.  86400   IN  TXT     "This example has multiple digests"
ns2.example.  3600    IN  AAAA    2001:db8::63
`

func TestContext_RootZoneDigest(t *testing.T) {
	ctx := tools.Context{
		Config: &tools.ContextConfig{
			Zone: "root-servers.net",
		},
		File:   bytes.NewBufferString(rootServers),
		Output: os.Stdout,
		Log:    Log,
	}
	if err := ctx.Digest(); err != nil {
		t.Errorf("%s", err)
	}
}

func TestContext_SimpleDigest(t *testing.T) {
	ctx := tools.Context{
		Config: &tools.ContextConfig{
			Zone: "example",
		},
		File:   bytes.NewBufferString(simpleZone),
		Output: os.Stdout,
		Log:    Log,
	}
	if err := ctx.VerifyDigest(); err != nil {
		t.Errorf("%s", err)
	}
}

func TestContext_ComplexDigest(t *testing.T) {
	ctx := tools.Context{
		Config: &tools.ContextConfig{
			Zone: "example",
		},
		File:   bytes.NewBufferString(complexZone),
		Output: os.Stdout,
		Log:    Log,
	}
	if err := ctx.VerifyDigest(); err != nil {
		t.Errorf("%s", err)
	}
}

func TestContext_SignedDigest(t *testing.T) {
	ctx := tools.Context{
		Config: &tools.ContextConfig{
			Zone: "uri.arpa",
		},
		File:   bytes.NewBufferString(signedZone),
		Output: os.Stdout,
		Log:    Log,
	}
	if err := ctx.VerifyDigest(); err != nil {
		t.Errorf("%s", err)
	}
}

func TestContext_MultiZONEMDDigest(t *testing.T) {
	ctx := tools.Context{
		Config: &tools.ContextConfig{
			Zone: "example",
		},
		File:   bytes.NewBufferString(multiZONEMDZone),
		Output: os.Stdout,
		Log:    Log,
	}
	if err := ctx.VerifyDigest(); err != nil {
		t.Errorf("%s", err)
	}
}

func TestContext_WrongDigest(t *testing.T) {
	ctx := tools.Context{
		Config: &tools.ContextConfig{
			Zone:    "root-servers.net",
			HashAlg: 1,
		},
		File:   bytes.NewBufferString(wrongRootServers),
		Output: os.Stdout,
		Log:    Log,
	}
	if err := ctx.VerifyDigest(); err == nil {
		t.Errorf("No error, but it should have been")
	}
}
