# DNS Tools: ZONEMD digest calculator and Signer (using PKCS11 and files)

[![Go Report Card](https://goreportcard.com/badge/github.com/niclabs/dns-tools)](https://goreportcard.com/report/github.com/niclabs/dns-tools) [![Build Status](https://travis-ci.org/niclabs/dns-tools.svg?branch=master)](https://travis-ci.org/niclabs/dns-tools)

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
git clone https://github.com/niclabs/dns-tools --branch v1.1.0
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
  - `--optout (-o)` Uses Opt-out, as specified in [RFC5155](https://tools.ietf.org/html/rfc5155).
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

- [Some incompatibilities with some common PKCS11-enabled libraries](https://github.com/niclabs/dns-tools/issues/8)
