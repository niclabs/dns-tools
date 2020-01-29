# HSM Tools: Checksum / Signer (using PKCS11)

[![Go Report Card](https://goreportcard.com/badge/github.com/niclabs/hsm-tools)](https://goreportcard.com/report/github.com/niclabs/hsm-tools) [![Build Status](https://travis-ci.org/niclabs/hsm-tools.svg?branch=master)](https://travis-ci.org/niclabs/hsm-tools)


## How to build hsm-tools

The following libraries should be installed in the systems which are going to use the compiled library:

* git
* gcc
* Go (1.12.3 or higher)

On [Debian 10 (Buster)](https://www.debian.org), with a sudo-enabled user, the commands to run to install dependencies and 
build are the following:

```bash
# Install requirements
sudo apt install build-essential pkg-config git
```

To compile it, you need to have `Go` installed on your machine. You can find how to install Go on [its official page](https://golang.org/doc/install).

Then, you need to clone, execute and build the repository: 

```
git clone https://github.com/niclabs/hsm-tools --branch v1.0
cd hsm-tools
go build
```

The file `hsm-tools` will be created on the same directory.

## Command Flags

the command has three modes:
* **Sign** allows to sign a zone. Its parameters are:
    * `--create-keys (-c)` creates the keys if they doesn't exist.
    * `--expiration-date (-e)` Allows to use a specific expiration date for certificate signing.
    * `--file (-f)` allows to select the file that will be signed.
    * `--key-label (-l)` allows to choose a label for the created keys (if not, they will have hsm-tools as name).
    * `--nsec3 (-3)` Uses NSEC3 for zone signing, as specified in [RFC5155](https://tools.ietf.org/html/rfc5155). If not activated, it uses NSEC.
    * `--optout (-o)` Uses Opt-out, as specified in [RFC5155](https://tools.ietf.org/html/rfc5155).
    * `--p11lib (-p)` selects the library to use as pkcs11 HSM driver.
    * `--user-key (-k)` HSM key, if not specified, the default is `1234`.
    * `--sign-algorithm (-a)` Sign algorithm used. It can be 'rsa' or 'ecdsa'.
    * `--zone (-z)` Zone name
* **Verify** Allows to verify a previously signed key. It only receives one parameter, `--file (-f)`, that is used as the input file for verification.
* **Reset Keys** Deletes all the keys from the HSM. Is a very dangerous command. It uses some parameters from `sign`, as `-p`, `l` and `k`.


## How to sign a zone

The following command signs a zone with NSEC3, using the file name `example.com` and creates a new file with the name `example.com.signed`, using the [DTC](https://github.com/niclabs/dtc) library. If there are not keys on the HSM, it creates them.

```
./hsm-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -c
```

Some arguments were omited, so they are set by their default value.

## How to verify a zone

The following command verifies the previously created key.

```
./hsm-tools verify -f ./example.com.signed
```

## How to delete keys

The folowing command removes the created keys with an specific tag, using the  [DTC](https://github.com/niclabs/dtc) library

```
./hsm-tools reset-keys -p ./dtc.so
```

## Config File

You can create a json config file with the structure of `config.sample.json` to set the variables.
The config file will be looked for at the following locations:

 * `/etc/hsm-tools/config.json`
 * `./config.json` (Current location)

You can also set the config file path using `--config` flag.

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
- [x] Reuse keys
- [x] Delete keys
- [x] Save zone to file

## Bugs
* [Some incompatibilities with some common PKCS11-enabled libraries](https://github.com/niclabs/hsm-tools/issues/8)
