package tools

// SignAlgorithm represents the algorithm used to sign a zone
// The numbers are the same the RFC defined for the algorithms.
type SignAlgorithm uint8

// Signing algorithms
const (
	RsaSha256       = 8  // RSA SHA256
	EcdsaP256Sha256 = 13 // ECDSA P256 SHA256
)

// StringToSignAlgorithm takes the name of an algorithm
var StringToSignAlgorithm = map[string]SignAlgorithm{
	"rsa":               RsaSha256,       // Default RSA case
	"rsa_sha256":        RsaSha256,       // Complete name
	"ecdsa":             EcdsaP256Sha256, // Default ECDSA case
	"ecdsa_p256":        EcdsaP256Sha256, // Alias for ecdsa_p256_sha256
	"ecdsa_p256_sha256": EcdsaP256Sha256, // Complete name
}
