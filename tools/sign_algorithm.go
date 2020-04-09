package tools

type SignAlgorithm uint8

const (
	RSA_SHA256        = 8
	ECDSA_P256_SHA256 = 13
)

var StringToSignAlgorithm = map[string]SignAlgorithm{
	"rsa":               RSA_SHA256,        // Default RSA case
	"rsa_sha256":        RSA_SHA256,        // Complete name
	"ecdsa":             ECDSA_P256_SHA256, // Default ECDSA case
	"ecdsa_p256":        ECDSA_P256_SHA256, // Alias for ecdsa_p256_sha256
	"ecdsa_p256_sha256": ECDSA_P256_SHA256, // Complete name
}
