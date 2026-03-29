package encryption

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KeyDerivationAlgorithm represents the algorithm used for key derivation
type KeyDerivationAlgorithm string

const (
	// Key derivation algorithms
	PBKDF2SHA512Algorithm KeyDerivationAlgorithm = "pbkdf2-sha512"
	PBKDF2SHA256Algorithm KeyDerivationAlgorithm = "pbkdf2-sha256"
	Argon2idAlgorithm     KeyDerivationAlgorithm = "argon2id"

	// Key sizes
	keySize = 32 // 256 bits for AES-256

	// Salt and nonce sizes
	saltSize  = 32
	nonceSize = 12

	// HMAC size
	hmacSize = 32

	// Algorithm indicator size
	AlgorithmIndicatorLength = 1

	// Key derivation constants
	argon2IterationsCount = 4    // Argon2 iterations (t)
	argon2MemoryKiB       = 9216 // Memory usage to 9 MiB (OWASP recommendation)
	argon2ThreadCount     = 1    // Threads (p) as per OWASP recommendation

	// These constants needed for tests
	Argon2idTime    = 4
	Argon2idMemory  = 9216
	Argon2idThreads = 1
	Argon2idKeyLen  = 32
	PBKDF2KeyLen    = 32

	// Constants for algorithm indicators
	Argon2idIndicator     byte = 0x01
	PBKDF2SHA256Indicator byte = 0x02
	PBKDF2SHA512Indicator byte = 0x03

	// Constants for secure logging
	secureLogPrefix = "****"
	secureLogSuffix = "****"
	secureLogLength = 8 // Number of characters to show in secure logs
)

// Argon2id parameters (OWASP recommended)
var (
	argon2Iterations = uint32(argon2IterationsCount) // Argon2 iterations (t)
	argon2Memory     = uint32(argon2MemoryKiB)       // Memory usage to 9 MiB (OWASP recommendation)
	argon2Threads    = uint8(argon2ThreadCount)      // Threads (p) as per OWASP recommendation

	// PBKDF2 parameters (OWASP recommended)
	pbkdf2SHA256Iterations = 600000 // PBKDF2-HMAC-SHA256: 600,000 iterations
	pbkdf2SHA512Iterations = 210000 // PBKDF2-HMAC-SHA512: 210,000 iterations
)

// Global variables
var (
	debugMode                     bool                   = false
	DefaultKeyDerivationAlgorithm KeyDerivationAlgorithm = Argon2idAlgorithm
)

// init initializes encryption parameters and checks the debug flag
func init() {
	// Check for the --debug argument
	for _, arg := range os.Args {
		if arg == "--debug" {
			debugMode = true
			break
		}
	}

	// Disable debug mode for benchmarks, but keep it for regular tests
	for _, arg := range os.Args {
		if strings.Contains(arg, "bench") {
			debugMode = false
			break
		}
	}
}

// secureLog outputs debug messages with sensitive data masked
func secureLog(format string, args ...interface{}) {
	if !debugMode {
		return
	}

	// Create a safe version of the format string
	safeFormat := strings.ReplaceAll(format, "%x", "%s")
	safeFormat = strings.ReplaceAll(safeFormat, "%d", "%s")
	safeFormat = strings.ReplaceAll(safeFormat, "%v", "%s")

	// Create safe arguments
	safeArgs := make([]interface{}, len(args))
	for i, arg := range args {
		switch arg.(type) {
		case []byte, string, int, int32, int64, uint, uint32, uint64:
			safeArgs[i] = secureLogPrefix + secureLogSuffix
		default:
			safeArgs[i] = secureLogPrefix + secureLogSuffix
		}
	}

	fmt.Printf(safeFormat, safeArgs...)
}

// Encrypt encrypts a plaintext string using AES-256 GCM with the specified key derivation algorithm and returns a base64-encoded ciphertext.
func Encrypt(password, plaintext string, algorithm ...KeyDerivationAlgorithm) (string, error) {
	secureLog("[DEBUG:Encrypt] Starting encryption process\n")
	secureLog("[DEBUG:Encrypt] Input length: %d bytes\n", len(plaintext))

	// Check password strength
	if err := ValidatePasswordStrength(password); err != nil {
		secureLog("[DEBUG:Encrypt] Password validation failed: %v\n", err)
		return "", err
	}

	if len(plaintext) == 0 {
		secureLog("[DEBUG:Encrypt] Error: plaintext is empty\n")
		return "", errors.New("plaintext cannot be empty")
	}

	// Set default algorithm if not specified
	var algo KeyDerivationAlgorithm
	if len(algorithm) > 0 && algorithm[0] != "" {
		algo = algorithm[0]
		secureLog("[DEBUG:Encrypt] Using provided algorithm: '%s'\n", algo)
	} else {
		algo = DefaultKeyDerivationAlgorithm
		secureLog("[DEBUG:Encrypt] Using default algorithm: '%s'\n", algo)
	}

	// Check for style suffixes
	styleSuffix := ""
	for _, suffix := range []string{"|", ">"} {
		if strings.HasSuffix(plaintext, suffix) {
			styleSuffix = suffix
			plaintext = plaintext[:len(plaintext)-len(suffix)]
			secureLog("[DEBUG:Encrypt] Detected style suffix: '%s'\n", styleSuffix)
			break
		}
	}

	// Compress plaintext
	secureLog("[DEBUG:Encrypt] Compressing plaintext\n")
	compressed, err := compress([]byte(plaintext))
	if err != nil {
		secureLog("[DEBUG:Encrypt] Compression failed: %v\n", err)
		return "", fmt.Errorf("failed to compress plaintext: %w", err)
	}
	secureLog("[DEBUG:Encrypt] Compression completed\n")

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		secureLog("[DEBUG:Encrypt] Failed to generate salt: %v\n", err)
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	secureLog("[DEBUG:Encrypt] Generated salt\n")

	// Derive key from password and salt
	secureLog("[DEBUG:Encrypt] Deriving key using algorithm: %s\n", algo)
	key, err := deriveKey(password, salt, algo)
	if err != nil {
		secureLog("[DEBUG:Encrypt] Key derivation failed: %v\n", err)
		return "", fmt.Errorf("failed to derive key: %w", err)
	}
	secureLog("[DEBUG:Encrypt] Key derived successfully\n")

	// Create secure buffer for the key
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		secureLog("[DEBUG:Encrypt] Failed to create secure buffer for key\n")
		return "", fmt.Errorf("failed to create secure buffer for key")
	}
	defer keyBuf.Destroy()
	secureLog("[DEBUG:Encrypt] Created secure key buffer\n")

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		secureLog("[DEBUG:Encrypt] Failed to generate nonce: %v\n", err)
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	secureLog("[DEBUG:Encrypt] Generated nonce\n")

	// Create AES cipher
	secureLog("[DEBUG:Encrypt] Creating AES cipher\n")
	block, err := aes.NewCipher(keyBuf.Bytes())
	if err != nil {
		secureLog("[DEBUG:Encrypt] Failed to create AES cipher: %v\n", err)
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		secureLog("[DEBUG:Encrypt] Failed to create GCM: %v\n", err)
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	secureLog("[DEBUG:Encrypt] AES-GCM cipher created successfully\n")

	// Encrypt data
	secureLog("[DEBUG:Encrypt] Encrypting data\n")
	ciphertext := aesGCM.Seal(nil, nonce, compressed, nil)
	secureLog("[DEBUG:Encrypt] Encryption completed\n")

	// Combine all components
	result := make([]byte, 0, 1+len(salt)+len(nonce)+len(ciphertext))
	result = append(result, byte(algo[0]))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	// Calculate HMAC for all data up to this point
	secureLog("[DEBUG:Encrypt] Calculating HMAC\n")
	hmacValue := computeHMAC(key, result, byte(algo[0]))
	secureLog("[DEBUG:Encrypt] HMAC calculated\n")

	// Add HMAC to the result
	result = append(result, hmacValue...)
	secureLog("[DEBUG:Encrypt] Final payload created\n")

	// Encode in base64
	encoded := base64.StdEncoding.EncodeToString(result)
	if styleSuffix != "" {
		encoded += styleSuffix
		secureLog("[DEBUG:Encrypt] Added style suffix: '%s'\n", styleSuffix)
	}
	secureLog("[DEBUG:Encrypt] Base64 encoding completed\n")

	// Securely wipe sensitive data
	memguard.WipeBytes(key)
	secureLog("[DEBUG:Encrypt] Sensitive data wiped\n")

	return encoded, nil
}

// Decrypt decrypts a base64-encoded ciphertext using AES-256 GCM with the specified key derivation algorithm and returns the plaintext.
func Decrypt(password, ciphertext string, algorithm ...KeyDerivationAlgorithm) (string, error) {
	secureLog("[DEBUG:Decrypt] Starting decryption process\n")
	secureLog("[DEBUG:Decrypt] Input length: %d bytes\n", len(ciphertext))

	if err := ValidatePasswordStrength(password); err != nil {
		secureLog("[DEBUG:Decrypt] Password validation failed: %v\n", err)
		return "", err
	}

	if len(ciphertext) == 0 {
		secureLog("[DEBUG:Decrypt] Error: ciphertext is empty\n")
		return "", errors.New("ciphertext cannot be empty")
	}

	// Set default algorithm if not provided
	var algo KeyDerivationAlgorithm
	if len(algorithm) > 0 && algorithm[0] != "" {
		algo = algorithm[0]
		secureLog("[DEBUG:Decrypt] Using provided algorithm: '%s'\n", algo)
	} else {
		algo = DefaultKeyDerivationAlgorithm
		secureLog("[DEBUG:Decrypt] Using default algorithm: '%s'\n", algo)
	}

	// Decode base64 ciphertext
	secureLog("[DEBUG:Decrypt] Decoding base64 input\n")
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		secureLog("[DEBUG:Decrypt] Base64 decoding failed: %v\n", err)
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	secureLog("[DEBUG:Decrypt] Base64 decoding completed\n")

	// Extract components
	if len(decoded) < saltSize+nonceSize+1+hmacSize {
		secureLog("[DEBUG:Decrypt] Error: payload too short\n")
		return "", errors.New("invalid ciphertext: too short")
	}

	algorithmByte := decoded[0]
	salt := decoded[1 : 1+saltSize]
	nonce := decoded[1+saltSize : 1+saltSize+nonceSize]
	encryptedData := decoded[1+saltSize+nonceSize : len(decoded)-hmacSize]
	hmacValue := decoded[len(decoded)-hmacSize:]

	secureLog("[DEBUG:Decrypt] Components extracted\n")

	// Derive key
	secureLog("[DEBUG:Decrypt] Deriving key using algorithm: %s\n", algo)
	key, err := deriveKey(password, salt, algo)
	if err != nil {
		secureLog("[DEBUG:Decrypt] Key derivation failed: %v\n", err)
		return "", fmt.Errorf("failed to derive key: %w", err)
	}
	secureLog("[DEBUG:Decrypt] Key derived successfully\n")

	// Create secure buffer for key
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		secureLog("[DEBUG:Decrypt] Failed to create secure buffer for key\n")
		return "", fmt.Errorf("failed to create secure buffer for key")
	}
	defer keyBuf.Destroy()
	secureLog("[DEBUG:Decrypt] Created secure key buffer\n")

	// Verify HMAC
	secureLog("[DEBUG:Decrypt] Verifying HMAC\n")
	hmacData := decoded[:len(decoded)-hmacSize]
	expectedHMAC := computeHMAC(key, hmacData, algorithmByte)
	if !hmac.Equal(expectedHMAC, hmacValue) {
		secureLog("[DEBUG:Decrypt] HMAC verification failed!\n")
		return "", errors.New("cipher: message authentication failed")
	}
	secureLog("[DEBUG:Decrypt] HMAC verified successfully\n")

	// Create cipher
	secureLog("[DEBUG:Decrypt] Creating AES cipher\n")
	block, err := aes.NewCipher(keyBuf.Bytes())
	if err != nil {
		secureLog("[DEBUG:Decrypt] Failed to create cipher: %v\n", err)
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		secureLog("[DEBUG:Decrypt] Failed to create GCM: %v\n", err)
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	secureLog("[DEBUG:Decrypt] AES-GCM cipher created successfully\n")

	// Decrypt data
	secureLog("[DEBUG:Decrypt] Decrypting data\n")
	decryptedData, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		secureLog("[DEBUG:Decrypt] Decryption failed: %v\n", err)
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}
	secureLog("[DEBUG:Decrypt] Decryption completed\n")

	// Decompress data
	secureLog("[DEBUG:Decrypt] Decompressing data\n")
	decompressedData, err := decompress(decryptedData)
	if err != nil {
		secureLog("[DEBUG:Decrypt] Decompression failed: %v\n", err)
		return "", fmt.Errorf("failed to decompress data: %w", err)
	}
	secureLog("[DEBUG:Decrypt] Decompression completed\n")
	secureLog("[DEBUG:Decrypt] Decryption completed successfully\n")

	return string(decompressedData), nil
}

// DecryptToString decrypts a base64-encoded ciphertext string and returns the plaintext as a string.
func DecryptToString(encrypted string, password string) (string, error) {
	secureLog("[DEBUG] DecryptToString call\n")

	// Ensure we're not trying to decrypt the key itself
	if len(encrypted) < 20 && strings.HasPrefix(password, encrypted) {
		return "", fmt.Errorf("error: attempting to decrypt the password itself, check argument order")
	}

	// Correctly pass arguments - first password, second encrypted text
	result, err := Decrypt(password, encrypted)
	if err != nil {
		secureLog("[DEBUG] Decryption failed\n")
		return "", err
	}

	secureLog("[DEBUG] Decryption successful\n")
	return result, nil
}

// min returns the smaller of x or y.
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// compress compresses data using gzip with best compression level
func compress(data []byte) ([]byte, error) {
	secureLog("[DEBUG:Compress] Starting compression\n")

	var buf bytes.Buffer

	// Create a gzip writer with best compression
	gzw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		secureLog("[DEBUG:Compress] Failed to create gzip writer: %v\n", err)
		return nil, fmt.Errorf("failed to create gzip writer: %w", err)
	}

	// Write data to the gzip writer
	if _, err := gzw.Write(data); err != nil {
		secureLog("[DEBUG:Compress] Failed to write data to gzip writer: %v\n", err)
		_ = gzw.Close()
		return nil, fmt.Errorf("failed to write to gzip writer: %w", err)
	}

	// Close the gzip writer to flush any pending data
	if err := gzw.Close(); err != nil {
		secureLog("[DEBUG:Compress] Failed to close gzip writer: %v\n", err)
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Get the compressed data
	compressed := buf.Bytes()
	secureLog("[DEBUG:Compress] Compression completed\n")

	return compressed, nil
}

// decompress decompresses gzipped data
func decompress(compressedData []byte) ([]byte, error) {
	secureLog("[DEBUG:Decompress] Starting decompression\n")

	// Create a reader for the compressed data
	buf := bytes.NewBuffer(compressedData)
	gzr, err := gzip.NewReader(buf)
	if err != nil {
		secureLog("[DEBUG:Decompress] Failed to create gzip reader: %v\n", err)
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	// Read the decompressed data
	decompressed, err := io.ReadAll(gzr)
	if err != nil {
		secureLog("[DEBUG:Decompress] Failed to read decompressed data: %v\n", err)
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	secureLog("[DEBUG:Decompress] Decompression completed\n")
	return decompressed, nil
}

// SetDefaultAlgorithm sets the default key derivation algorithm
func SetDefaultAlgorithm(algorithm KeyDerivationAlgorithm) {
	DefaultKeyDerivationAlgorithm = algorithm
}

// GetAvailableKeyDerivationAlgorithms returns the list of available key derivation algorithms
func GetAvailableKeyDerivationAlgorithms() []KeyDerivationAlgorithm {
	return []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}
}

// computeHMAC computes the HMAC for given data using the provided key.
func computeHMAC(key, data []byte, algorithm ...byte) []byte {
	secureLog("[DEBUG:HMAC] Computing HMAC\n")

	// Create secure buffer for the key
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		secureLog("[DEBUG:HMAC] Failed to create secure buffer for key\n")
		return nil
	}
	defer keyBuf.Destroy()
	secureLog("[DEBUG:HMAC] Created secure buffer for key\n")

	// Create HMAC with key from secure buffer
	h := hmac.New(sha256.New, keyBuf.Bytes())

	// Write data directly to HMAC (not using secure buffer for data)
	h.Write(data)

	// Add algorithm byte to HMAC
	if len(algorithm) > 0 {
		alg := algorithm[0]
		secureLog("[DEBUG:HMAC] Including algorithm byte in HMAC calculation\n")
		h.Write([]byte{alg})
	}

	// Get the result
	result := h.Sum(nil)
	secureLog("[DEBUG:HMAC] HMAC calculation complete\n")

	return result
}

// deriveKey derives a 32-byte key from the given password and salt using the specified algorithm.
func deriveKey(password string, salt []byte, algorithm KeyDerivationAlgorithm) ([]byte, error) {
	secureLog("[DEBUG:KeyDerive] Starting key derivation with algorithm: %s\n", algorithm)

	// Derive key in regular memory
	var key []byte

	switch algorithm {
	case PBKDF2SHA512Algorithm:
		secureLog("[DEBUG:KeyDerive] Using PBKDF2-SHA512\n")
		key = pbkdf2.Key([]byte(password), salt, pbkdf2SHA512Iterations, keySize, sha512.New)
		secureLog("[DEBUG:KeyDerive] PBKDF2-SHA512 completed\n")
	case PBKDF2SHA256Algorithm:
		secureLog("[DEBUG:KeyDerive] Using PBKDF2-SHA256\n")
		key = pbkdf2.Key([]byte(password), salt, pbkdf2SHA256Iterations, keySize, sha256.New)
		secureLog("[DEBUG:KeyDerive] PBKDF2-SHA256 completed\n")
	case Argon2idAlgorithm:
		secureLog("[DEBUG:KeyDerive] Using Argon2id\n")
		key = argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Threads, keySize)
		secureLog("[DEBUG:KeyDerive] Argon2id completed\n")
	default:
		err := fmt.Errorf("unsupported key derivation algorithm: %s", algorithm)
		secureLog("[DEBUG:KeyDerive] Error: %v\n", err)
		return nil, err
	}

	// Create a copy of the key to return
	result := make([]byte, keySize)
	copy(result, key)
	secureLog("[DEBUG:KeyDerive] Key derivation successful\n")

	// Wipe the original key from memory
	memguard.WipeBytes(key)
	secureLog("[DEBUG:KeyDerive] Wiped original key from memory\n")

	return result, nil
}
