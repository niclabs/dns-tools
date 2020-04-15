package tools

// SignAlgorithm represents the algorithm used to sign a zone
// The numbers are the same the RFC defined for the algorithms.
type SignAlgorithm uint8

const (
	RSA_SHA256        = 8  // RSA SHA256
	ECDSA_P256_SHA256 = 13 // ECDSA P256 SHA256
)

// StringToSignAlgorithm takes the name of an algorithm
var StringToSignAlgorithm = map[string]SignAlgorithm{
	"rsa":               RSA_SHA256,        // Default RSA case
	"rsa_sha256":        RSA_SHA256,        // Complete name
	"ecdsa":             ECDSA_P256_SHA256, // Default ECDSA case
	"ecdsa_p256":        ECDSA_P256_SHA256, // Alias for ecdsa_p256_sha256
	"ecdsa_p256_sha256": ECDSA_P256_SHA256, // Complete name
}
