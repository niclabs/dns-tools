# dhsm-signer
DNS zone Signer for HSMs (using PKCS11)

req: go version go1.12.3 linux/amd64

Features:
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
- [ ] Save zone to file

Bugs:

None (known)
