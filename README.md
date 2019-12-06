DNS zone Signer for HSMs (using PKCS11)

## How to build dhsm-signer

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
git clone https://github.com/niclabs/dhsm-signer --branch v1.0
cd dhsm-signer
go build
```

The file `dhsm-signer` will be created on the same directory.


## Features

- [x] Read zone
- [x] Parse zone
- [x] Create keys in HSM
- [x] Sign using PKCS11 (for HSMs):
    - [x] RSA
    - [ ] ECDSAP
    - [ ] SHA-1
    - [ ] SHA128
    - [x] SHA256
    - [ ] SHA512
- [x] Reuse keys
- [x] Delete keys
- [x] Save zone to file

## Bugs
* [Some incompatibilities with some common PKCS11-enabled libraries](https://github.com/niclabs/dhsm-signer/issues/8)
