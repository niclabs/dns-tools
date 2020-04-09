package tools_test

import (
	"bytes"
	"github.com/niclabs/dns-tools/tools"
	"log"
	"os"
	"testing"
)

// Using default softHSM configuration. Change it if necessary.
const p11Lib = "/usr/lib/libsofthsm2.so"
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

const complexZone = `
example.     86400    IN  SOA     ns1 admin 2018031900 1800 900 604800 86400 
			 86400    IN  NS      ns1
			 86400    IN  NS      ns2
			 86400    IN  ZONEMD  2018031900 1 1 626637812169d7abfcb24f13cb704f13b8a131fee1c3bc7329144fa5ec2608a41b596d41ff8c8310b2897e73f6e521fc
ns1           3600    IN  A       203.0.113.63
ns2           3600    IN  AAAA    2001:db8::63
occluded.sub  7200    IN  TXT     "I'm occluded but must be digested"
sub           7200    IN  NS      ns1
duplicate     300     IN  TXT     "I must be digested just once"
duplicate     300     IN  TXT     "I must be digested just once"
foo.test.     555     IN  TXT     "out-of-zone data must be excluded"
non-apex      900     IN  ZONEMD  2018031900 1 1 616c6c6f776564206275742069676e6f7265642e20616c6c6f776564206275742069676e6f7265642e20616c6c6f7765
`

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
uri.arpa.       3600    IN      ZONEMD  2018100702 1 1 cc4a0b6556272fc739b8ff74b80b4a43ac9575d91445ecc0dc22f509fa27c62448a7100660bbdb4c90667424b734956b 
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
root-servers.net.     3600000 IN  ZONEMD  2018091100 1 1 4fb752b314e4dccb845832b611590b669a80daebb736d4bd22aa76ec066737c79185c1f7dfd49ec91d9523e6240ea2c4
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
root-servers.net.     3600000 IN  ZONEMD  2018091100 1 1 4fb752b314e4dccb845832b611590b669a80daebb736d4bd22aa76ec06 6737c79185c1f7dfd49ec91d9523e6240ea2c5` // <- the last character should have been 4

const multiZONEMDZone = `
example.      86400   IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
example.      86400   IN  NS      ns1.example.
example.      86400   IN  NS      ns2.example.
example.      86400   IN  ZONEMD  2018031900 1 1 366d22ea3bd8df440fa44b6213359d9b1f73bb9d8dd67a1b4c0bdf6f0b3657c50316f770fbb030570c06adb87c121431 
example.      86400   IN  ZONEMD  2018031900 1 240 e2d523f654b9422a96c5a8f44607bbee 
example.      86400   IN  ZONEMD  2018031900 1 241 5732dd91240611f8314adb6b4769bdd2 
example.      86400   IN  ZONEMD  2018031900 1 242 7c32e06779315c7d81ba8c72f5cf9116496b6395 
example.      86400   IN  ZONEMD  2018031900 1 243 183770af4a629f802e674e305b8d0d113dfe0837 
example.      86400   IN  ZONEMD  2018031900 1 244 e1846540e33a9e4189792d18d5d131f605fc283e 
example.      86400   IN  ZONEMD  2018031900 240 1 e1846540e33a9e4189792d18d5d131f605fc283e 
ns1.example.  3600    IN  A       203.0.113.63
ns2.example.  86400   IN  TXT     "This example has multiple digests"
ns2.example.  3600    IN  AAAA    2001:db8::63
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
	if err := ctx.VerifyFile(); err != nil {
		t.Errorf("%s", err)
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
			Zone: "root-servers.net",
		},
		File:   bytes.NewBufferString(wrongRootServers),
		Output: os.Stdout,
		Log:    Log,
	}
	if err := ctx.VerifyDigest(); err == nil {
		t.Errorf("No error, but it should have been")
	}
}
