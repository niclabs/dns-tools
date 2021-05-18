# DNS Tools: DNS signer (using PKCS11 and files) and ZONEMD digest calculator 
[![Go Report Card](https://goreportcard.com/badge/github.com/niclabs/dns-tools)](https://goreportcard.com/report/github.com/niclabs/dns-tools) [![Build Status](https://travis-ci.org/niclabs/dns-tools.svg?branch=master)](https://travis-ci.org/niclabs/dns-tools)

(originally written by Hugo Salgado at [this blog post (in Spanish)](https://blog.nic.cl/2021/04/dns-tools-herramienta-para-verificar.html))

Currently there are several solutions that allow automating the DNSSEC
signing of domains, integrated into the same services that normally
provide DNS. In the open source area, the most widely used ones allow
DNSSEC to be activated with a few instructions in the configuration,
without worrying about keys or signatures.

However, it is always good to have tools that allow verifications or
even signatures in a more low-level way. There are often use cases
where someone prefers to have more control, or to integrate with
non-standard internal systems.

We present **dns-tools**, a command line tool (CLI), written in Go
language, that allows you to sign with DNSSEC a zone, create zone
*integrity* records called ZONEMD, and in turn validate these signatures
and records. This tool was created by [NICLabs](https://niclabs.cl/),
the laboratory of NIC Chile. It is maintained as open source code on
github with MIT license.

One of the most outstanding things, and what makes it a unique tool, is
its integration with another NICLabs project called *dtc: distributed
threshold signatures*, which allows using a group of "sub"-signers
that provide greater security against the case of having the keys *"on
disk"*, as is the normal case of the signers integrated in DNS
software. Currently there are basically two scales of security with
respect to DNSSEC keys: either they are kept on disk on a single
machine, or they are kept in an external HSM. The dns-tools solution
is in the middle of these two, since on the one hand there is no risk
of having a complete key on disk; and on the other hand it is much
cheaper than buying a dedicated HSM.

## Zone Integrity (ZONEMD)

The dns-tools tool has support for the new ZONEMD registry, created at
the end of 2020. This registry allows to have a *checksum* of the
complete zone file, which allows the one receiving a zone to verify
that it is correct. It is similar to the SHA*SUM files that accompany
certain software, which makes it possible to ensure that a download was
not maliciously modified, or that it had transmission failures.

Its usefulness is mainly for certain systems that transfer zones using
the AXFR protocol internal to the DNS, which allows each of the
receivers of a zone to verify that it is correct. It is also thought to
be useful for the distribution of certain zones outside the DNS, as is
the case for example of the DNS root, which is published on websites
or FTP, and that thanks to the ZONEMD record can be verified after
downloading.

So, the dns-tools tool allows to generate ZONEMD records, and to verify
the existing ones. It was one of the first implementations of this new
standard, and it complied with the compatibility tests performed by the
authors of the document.

One important thing is that in order to generate ZONEMD records it is a
requirement that the zone is also signed with DNSSEC, by the same tool.
And therefore it is necessary to have access to the keys.

On the contrary and as in the case of DNSSEC validation, to verify a
ZONEMD record it is enough to have the zone file.

```
  $ dns-tools verify -f example.cl.zone.signed
  dns-tools] 2021/04/07 11:53:08 Zone parsed is example.cl.
  Validating Scheme 1, HashAlg 1... ok
  dns-tools] 2021/04/07 11:53:08 Zone Digest: Verified Successfully.
```

# Distributed DNSSEC signing

dns-tools allows you to sign a zone by passing the keys directly to
disk, in the style of most automatic signers, but also allows the use
of the *PKCS11* interface to have an external keystore, either also on
disk but managed by a different process (such as *SoftHSM*), or an
external hardware device specialized in cryptography, the HSM.

This is where it is possible to integrate dns-tools with another system
developed by NICLabs called ["dtc" (Distributed Threshold Cryptography
Library Signer)](https://github.com/niclabs/dtc/wiki), which through
this same PKCS11 interface allows the use of "signer nodes" that share
*pieces* of a key and must comply with certain *consensus* rules to
generate a definitive signature. The details of this will be the subject
of another article.

The important thing is to be clear that the command:

```
  $ dns-tools sign file -f example.cl.zone -K ksk.pem -Z zsk.pem
```

takes a normal zone file, DNSSEC keys on disk file, and generates a
correctly signed zone with DNSSEC. In case the keys do not exist,
dns-tools can also create them. It is also possible to use the syntax:

```
  $ dns-tools sign pkcs11 -f example.cl.zone -p /usr/lib/dtc.so
```

which allows using the PKCS11 interface for communication with an
external keystore. The corresponding library must be specified with the
-p option.

The inverse operation, checking or validating signatures, is very
useful to be used also as a *"second opinion"* in the case of using
a different signing software. It is a very good practice that when
having any signature, another completely independent software is used
to verify the signatures, in order to be sure that the process is
correct. In this case its use is much simpler, since it is not
necessary to access the keys:

```
  $ dns-tools verify -f ejemplo.cl.zone.signed
  [dns-tools] 2021/04/21 12:35:43 Zone parsed is ejemplo.cl.
  Validating Scheme 1, HashAlg 1... ok
  [dns-tools] 2021/04/21 12:35:43 Zone Digest: Verified Successfully.
```

We invite you to try the tool and use it. As any open source project we
are attentive to the needs of the community, so if you feel that
something is missing or want to collaborate with any correction, please
enter your "issues" to the github and we will improve it together!

## How to build dns-tools

The following libraries should be installed in the systems which are going to use the compiled library:

- git
- gcc
- Go (1.12.3 or higher)

On [Debian 10 (Buster)](https://www.debian.org), with a sudo-enabled user, the commands to run to install dependencies and
build are the following:

```bash
# Install requirements
sudo apt install build-essential pkg-config git
```

To compile it, you need to have `Go` installed on your machine. You can find how to install Go on [its official page](https://golang.org/doc/install).

Then, you need to clone, execute and build the repository:

```
git clone https://github.com/niclabs/dns-tools
cd dns-tools
go build
```

The file `dns-tools` will be created on the same directory.

## Command Flags

the command has three modes:

- **Verify** `dns-tools verify` allows to verify a previously signed and/or digested zone. It receives the following parameters:
  - `--file (-f)` is used as the input file for verification.
  - `--zone (-z)` Zone name.
  - `--verify-threshold-date (-t)` Exact date it needs to be before a signature expiration to be considered as expired by the verifier. It is ignored if --verify-threshold-duration is set. Default is tomorrow.
  - `--verify-threshold-duration (-T)` Number of days it needs to be before a signature expiration to be considered as valid by the verifier. It overrides `--verify-threshold-date` if it is defined. Default is empty.

- **Reset PKCS#11 Keys** `dns-tools reset-pkcs11-keys` Deletes all the keys from the HSM. Is a very dangerous command. It uses some parameters from `sign`, as `-p`, `-l` and `-k`.
- **Sign** allows to sign a zone. Its common parameters are:
  - `--create-keys (-c)` creates the keys if they do not exist. If they exist, they are overwritten.
  - `--rrsig-expiration-date (-E)` Allows to use a specific expiration date for RRSIG signatures. It can be overrided by --rrsig-duration.
  - `--rrsig-duration (-D)` Allows to use a expiration date for RRSIG signatures relative to current time. It overrides --rrsig-expiration-date. Default value is empty.
  - `--verify-threshold-date (-t)` Exact date it needs to be before a signature expiration to be considered as expired by the verifier. It is ignored if --verify-threshold-duration is set. Default is tomorrow.
  - `--verify-threshold-duration (-T)` Number of days it needs to be before a signature expiration to be considered as valid by the verifier. It overrides `--verify-threshold-date` if it is defined. Default is empty.
  - `--file (-f)` allows to select the file that will be signed.
  - `--nsec3 (-3)` Uses NSEC3 for zone signing, as specified in [RFC5155](https://tools.ietf.org/html/rfc5155). If not activated, it uses NSEC.
  - `--nsec3-iterations` If --nsec3 is active, defines the number of iterations in NSEC3 hashing. The default value is 0.
  - `--nsec3-salt-value` If --nsec3 is active and its value is not empty, defines the hexadecimal value representation of the salt that will be used. It is disabled by default.
  - `--nsec3-salt-length` If --nsec3 is active and --nsec3-salt-value is empty, this value defines the byte length for an autogenerated salt. Its default value is 8.
  - `--opt-out (-x)` Uses Opt-out, as specified in [RFC5155](https://tools.ietf.org/html/rfc5155).
  - `--p11lib (-p)` selects the library to use as pkcs11 HSM driver.
  - `--sign-algorithm (-a)` Sign algorithm used. It can be 'rsa' or 'ecdsa'.
  - `--zone (-z)` Zone name.
  - `--digest (-d)` If true, the signature also creates a [Digest](https://tools.ietf.org/html/draft-ietf-dnsop-dns-zone-digest-05.html) over the zone
  * `--info (-i)` Add a TXT RR to the zone with signing information (signer software, mode and library used if PKCS#11)
  - `--lazy (-L)` Signs only if it is needed (output file does not exist, already signed zone is invalid or original zone was modified after signed zone). If it is not needed, it returns with an error.

- **ZONEMD calculation** Allows to generate a [ZONEMD](https://tools.ietf.org/html/draft-ietf-dnsop-dns-zone-digest-05.html) RR over the zone. It allows the following commands:
  - `--file (-f)` Input zone file
  - `--output (-o)` Output for zone file
  - `--info (-i)` Add a TXT RR to the zone with signing information (signer software, mode and library used if PKCS#11)
  -  `--hash-digest` Hash algorithm for digest, default: 1 (SHA384), also accepted 2 (SHA512) 

## Signing modes

Sign can be used in two modes:

- **PKCS#11**: `dns-tools sign pkcs11` connects to a PKCS#11 enabled device to sign the zone. It considers the following options:
  - `--key-label (-l)` allows to choose a label for the created keys (if not, they will have dns-tools as name).
  - `--user-key (-k)` HSM key, if not specified, the default key used is `1234`.
- **File**: `dns-tools sign file` uses two PEM files with PKCS#8 encoded keys. It requires to define two options:
  - `--zsk-file (-Z)` ZSK PEM File location. If `--create-keys` is enabled, the file will be created and any previous key will be overriden, so use it with care.
  - `--ksk-file (-K)` KSK PEM File location. If `--create-keys` is enabled, the file will be created and any previous key will be overriden, so use it with care.

### Using a PKCS#11 device

The following command signs a zone with NSEC3, using the file name `example.com` and creates a new file with the name `example.com.signed`, using the [DTC](https://github.com/niclabs/dtc) library. If there are not keys on the HSM, it creates them.

```
./dns-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -c
```

### Using a PEM file

The following command signs a zone with NSEC3, using the file name `example.com` and creates a new file with the name `example.com.signed`, using the [DTC](https://github.com/niclabs/dtc) library. If there are not keys on the HSM, it creates them.

```
./dns-tools sign file -f ./example.com -3 -z example.com -o example.com.signed -K ksk.pem -Z zsk.pem -c
```

Some arguments were omitted, so they are set by their default value.

## How to verify a zone

The following command verifies a previously signed (or digested) zone.

```
./dns-tools verify -f ./example.com.signed -z example.com
```

## How to add ZONEMD RR to a zone

The following command creates an output file with a ZONEMD RR:

```
./dns-tools digest -f ./example.com.signed -o ./example-digest.com.signed
```

## How to delete PKCS11 keys

The following command removes the created keys with an specific tag, using the [DTC](https://github.com/niclabs/dtc) library

```
./dns-tools reset-pkcs11-keys -p ./dtc.so
```

## Config File

You can create a json config file with the structure of `config.sample.json` to set the variables.
The config file will be looked for at the following locations:

- `/etc/dns-tools/dns-tools-config.json`
- `./dns-tools-config.json` (Current location)

You can also set the config file path using `--config` flag.

### Duration format

The fields `--{zsk,ksk,rrsig}-duration` are parsed using the following regular expression:

`(<n> <time_keyword>)(,? +<n> <time_keyword>)*`

Where:

- `<n>` corresponds to a non-negative integer number.
- `<time_keyword>` is a value in the following list:
  - `s`, `sec`, `secs`, `seconds` for seconds.
  - `min`, `minute`, `mins`, `minutes` for minutes
  - `h`, `hr`, `hour`, `hrs`, `hours` for hours
  - `w`, `week`, `weeks` for weeks
  - `m`, `month`, `months` for months
  - `y`, `year`, `years` for years


In other words, the duration units are separated by one or more spaces, ignoring plurals and commas at the end of each duration definition.

The relative duration definition is used with the time that the command is executed.

Examples:

* 1 year 3 months
* 1 hour 3 seconds
* 3 weeks 2 months 4 seconds 1 year

## Features

- [x] Read zone
- [x] Parse zone
- [x] Create keys in HSM
- [x] Sign using PKCS11 (for HSMs):
  - [x] RSA
  - [x] ECDSA
  - [ ] SHA-1
  - [ ] SHA128
  - [x] SHA256
  - [ ] SHA512
- [x] Sign using PKCS#8-encoded PEM keys:
  - [x] RSA
  - [x] ECDSA
  - [ ] SHA-1
  - [ ] SHA128
  - [x] SHA256
  - [ ] SHA512
- [x] Calculate ZONEMD RRs
- [x] Verify signed/digested zones
- [x] Reuse keys
- [x] Delete keys
- [x] Save zone to file

## Bugs

- ~[Some incompatibilities with some common PKCS11-enabled libraries](https://github.com/niclabs/dns-tools/issues/8)~
