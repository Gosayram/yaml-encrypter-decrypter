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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"github.com/awnumar/memguard"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

var (
	// Named logger for encryption component
	encryptionLogger = logger.Named("encryption")
)

// KeyDerivationAlgorithm represents the algorithm used for key derivation
type KeyDerivationAlgorithm string

const (
	// PBKDF2SHA512Algorithm is the PBKDF2-SHA512 key derivation algorithm
	PBKDF2SHA512Algorithm KeyDerivationAlgorithm = "pbkdf2-sha512"
	// PBKDF2SHA256Algorithm is the PBKDF2-SHA256 key derivation algorithm
	PBKDF2SHA256Algorithm KeyDerivationAlgorithm = "pbkdf2-sha256"
	// Argon2idAlgorithm is the Argon2id key derivation algorithm
	Argon2idAlgorithm KeyDerivationAlgorithm = "argon2id"

	// Key sizes
	keySize = 32 // 256 bits for AES-256

	// Salt and nonce sizes
	saltSize  = 32
	nonceSize = 12

	// HMAC size
	hmacSize = 32

	// AlgorithmIndicatorLength is the length of the algorithm indicator byte
	AlgorithmIndicatorLength = 1

	// Cipher metadata/header constants (format v2)
	headerMagicPrefix     = "YED"
	headerMagicLength     = 3
	headerVersionLength   = 1
	headerTimestampLength = 10 // unix timestamp in seconds, zero-padded ASCII
	headerV2Version       = 0x02
	headerV2Length        = headerMagicLength + headerVersionLength + headerTimestampLength + AlgorithmIndicatorLength

	// Human-readable envelope constants.
	visibleEnvelopeVersion = "v2"
	visibleEnvelopePrefix  = visibleEnvelopeVersion + ";"

	// Key derivation constants
	argon2IterationsCount = 4    // Argon2 iterations (t)
	argon2MemoryKiB       = 9216 // Memory usage to 9 MiB (OWASP recommendation)
	argon2ThreadCount     = 1    // Threads (p) as per OWASP recommendation

	// Argon2idTime is the Argon2id time parameter
	Argon2idTime = 4
	// Argon2idMemory is the Argon2id memory parameter in KiB
	Argon2idMemory = 9216
	// Argon2idThreads is the Argon2id thread count parameter
	Argon2idThreads = 1
	// Argon2idKeyLen is the Argon2id key length in bytes
	Argon2idKeyLen = 32
	// PBKDF2KeyLen is the PBKDF2 key length in bytes
	PBKDF2KeyLen = 32

	// Argon2idIndicator is the byte indicator for Argon2id algorithm
	Argon2idIndicator byte = 0x01
	// PBKDF2SHA256Indicator is the byte indicator for PBKDF2-SHA256 algorithm
	PBKDF2SHA256Indicator byte = 0x02
	// PBKDF2SHA512Indicator is the byte indicator for PBKDF2-SHA512 algorithm
	PBKDF2SHA512Indicator byte = 0x03
	// legacyArgon2Indicator is the legacy byte indicator for Argon2
	legacyArgon2Indicator byte = 'a'
	// legacyPBKDF2Indicator is the legacy byte indicator for PBKDF2
	legacyPBKDF2Indicator byte = 'p'

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
	defaultKeyDerivationAlgorithm KeyDerivationAlgorithm = Argon2idAlgorithm
	defaultAlgorithmMu            sync.RWMutex
)

// CipherMetadata describes optional metadata embedded into ciphertext header.
type CipherMetadata struct {
	FormatVersion int
	CreatedAt     time.Time
	Algorithm     KeyDerivationAlgorithm
}

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

	encryptionLogger.Debug(fmt.Sprintf(safeFormat, safeArgs...))
}

// Encrypt encrypts a plaintext string using AES-256 GCM with the specified key derivation algorithm and returns a base64-encoded ciphertext.
func Encrypt(password, plaintext string, algorithm ...KeyDerivationAlgorithm) (string, error) {
	encryptionLogger.Debug("Starting encryption process",
		zap.Int("plaintext_length", len(plaintext)),
		zap.Bool("algorithm_provided", len(algorithm) > 0),
	)

	// Check password strength
	if err := ValidatePasswordStrength(password); err != nil {
		encryptionLogger.Debug("Password validation failed", zap.Error(err))
		return "", err
	}

	if len(plaintext) == 0 {
		encryptionLogger.Debug("Error: plaintext is empty")
		return "", errors.New("plaintext cannot be empty")
	}

	// Set default algorithm if not specified
	var algo KeyDerivationAlgorithm
	if len(algorithm) > 0 && algorithm[0] != "" {
		algo = algorithm[0]
		encryptionLogger.Debug("Using provided algorithm", zap.String("algorithm", string(algo)))
	} else {
		algo = getDefaultAlgorithm()
		encryptionLogger.Debug("Using default algorithm", zap.String("algorithm", string(algo)))
	}

	indicator, err := algorithmToIndicator(algo)
	if err != nil {
		return "", err
	}

	// Check for style suffixes
	styleSuffix := ""
	for _, suffix := range []string{"|", ">"} {
		if strings.HasSuffix(plaintext, suffix) {
			styleSuffix = suffix
			plaintext = strings.TrimSuffix(plaintext, suffix)
			encryptionLogger.Debug("Detected style suffix", zap.String("suffix", styleSuffix))
			break
		}
	}

	// Compress plaintext
	encryptionLogger.Debug("Compressing plaintext")
	compressed, err := compress([]byte(plaintext))
	if err != nil {
		encryptionLogger.Debug("Compression failed", zap.Error(err))
		return "", fmt.Errorf("failed to compress plaintext: %w", err)
	}
	encryptionLogger.Debug("Compression completed")

	// Generate random salt
	encryptionLogger.Debug("Generating salt")
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		encryptionLogger.Debug("Failed to generate salt", zap.Error(err))
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	encryptionLogger.Debug("Salt generated")

	// Derive key from password and salt
	encryptionLogger.Debug("Deriving key from password", zap.String("algorithm", string(algo)))
	key, err := deriveKey(password, salt, algo)
	if err != nil {
		encryptionLogger.Debug("Key derivation failed", zap.Error(err))
		return "", fmt.Errorf("failed to derive key: %w", err)
	}
	encryptionLogger.Debug("Key derivation successful", zap.String("algorithm", string(algo)))

	// Create secure buffer for the key
	encryptionLogger.Debug("Creating secure buffer for key")
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		encryptionLogger.Debug("Failed to create secure buffer for key")
		return "", fmt.Errorf("failed to create secure buffer for key")
	}
	encryptionLogger.Debug("Secure key buffer created")

	// Generate random nonce
	encryptionLogger.Debug("Generating nonce")
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		encryptionLogger.Debug("Failed to generate nonce", zap.Error(err))
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	encryptionLogger.Debug("Nonce generated")

	// Create AES cipher
	encryptionLogger.Debug("Creating AES cipher")
	block, err := aes.NewCipher(keyBuf.Bytes())
	if err != nil {
		encryptionLogger.Debug("Failed to create AES cipher", zap.Error(err))
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		encryptionLogger.Debug("Failed to create GCM", zap.Error(err))
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	encryptionLogger.Debug("AES-GCM cipher created successfully")

	// Encrypt data
	encryptionLogger.Debug("Encrypting data")
	ciphertext := aesGCM.Seal(nil, nonce, compressed, nil)
	encryptionLogger.Debug("Encryption completed")

	// Build versioned metadata header:
	// [magic:3][format_version:1][created_at_unix:8][algorithm_indicator:1]
	header := make([]byte, 0, headerV2Length)
	header = append(header, []byte(headerMagicPrefix)...)
	header = append(header, byte(headerV2Version))
	createdAtUnix := time.Now().Unix()
	timestamp := fmt.Sprintf("%010d", createdAtUnix)
	header = append(header, []byte(timestamp)...)
	header = append(header, indicator)

	// Combine all components
	result := make([]byte, 0, len(header)+len(salt)+len(nonce)+len(ciphertext))
	result = append(result, header...)
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	// Calculate HMAC for all data up to this point
	encryptionLogger.Debug("Calculating HMAC",
		zap.ByteString("header", header),
		zap.ByteString("nonce", nonce),
		zap.ByteString("ciphertext", ciphertext),
	)
	hmacValue := computeHMAC(key, result, indicator)
	encryptionLogger.Debug("HMAC calculated",
		zap.ByteString("hmac_value", hmacValue),
	)

	// Add HMAC to the result
	result = append(result, hmacValue...)
	encryptionLogger.Debug("Final payload created",
		zap.ByteString("final_payload", result),
	)

	// Encode in base64 and wrap into a visible metadata envelope.
	encodedPayload := base64.StdEncoding.EncodeToString(result)
	encoded := buildVisibleCipherEnvelope(encodedPayload, algo, time.Unix(createdAtUnix, 0).UTC())
	if styleSuffix != "" {
		encoded += styleSuffix
		encryptionLogger.Debug("Added style suffix", zap.String("suffix", styleSuffix))
	}
	encryptionLogger.Debug("Base64 encoding completed")

	// Securely wipe sensitive data
	memguard.WipeBytes(key)
	encryptionLogger.Debug("Sensitive data wiped")

	return encoded, nil
}

// Decrypt decrypts a base64-encoded ciphertext using AES-256 GCM with the specified key derivation algorithm and returns the plaintext.
func Decrypt(password, ciphertext string, algorithm ...KeyDerivationAlgorithm) (string, error) {
	encryptionLogger.Debug("Starting decryption process",
		zap.Int("ciphertext_length", len(ciphertext)),
		zap.Bool("algorithm_provided", len(algorithm) > 0),
	)

	if err := ValidatePasswordStrength(password); err != nil {
		encryptionLogger.Debug("Password validation failed", zap.Error(err))
		return "", err
	}

	if len(ciphertext) == 0 {
		encryptionLogger.Debug("Error: ciphertext is empty")
		return "", errors.New("ciphertext cannot be empty")
	}

	base64Payload, _, err := parseVisibleCipherEnvelope(ciphertext)
	if err != nil {
		return "", err
	}

	// Decode base64 ciphertext
	encryptionLogger.Debug("Decoding base64 input")
	decoded, err := base64.StdEncoding.DecodeString(base64Payload)
	if err != nil {
		encryptionLogger.Debug("Base64 decoding failed", zap.Error(err))
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	encryptionLogger.Debug("Base64 decoding completed")

	algorithmByte, salt, nonce, encryptedData, hmacData, hmacValue, _, err := parseCipherPayload(decoded)
	if err != nil {
		encryptionLogger.Debug("Failed to parse payload", zap.Error(err))
		return "", err
	}
	encryptionLogger.Debug("Components extracted")

	candidates, err := resolveDecryptionAlgorithms(algorithmByte, algorithm...)
	if err != nil {
		return "", err
	}

	for _, algo := range candidates {
		decrypted, decryptErr := decryptWithAlgorithm(password, algo, algorithmByte, salt, nonce, encryptedData, hmacData, hmacValue)
		if decryptErr == nil {
			return decrypted, nil
		}
		if !errors.Is(decryptErr, errAuthenticationFailed) {
			return "", decryptErr
		}
	}

	encryptionLogger.Debug("All candidate algorithms failed HMAC verification")
	return "", errAuthenticationFailed
}

// DecryptToString decrypts a base64-encoded ciphertext string and returns the plaintext as a string.
func DecryptToString(encrypted string, password string) (string, error) {
	encryptionLogger.Debug("DecryptToString call")

	// Ensure we're not trying to decrypt the key itself
	if len(encrypted) < 20 && strings.HasPrefix(password, encrypted) {
		return "", fmt.Errorf("error: attempting to decrypt the password itself, check argument order")
	}

	// Correctly pass arguments - first password, second encrypted text
	result, err := Decrypt(password, encrypted)
	if err != nil {
		encryptionLogger.Debug("Decryption failed", zap.Error(err))
		return "", err
	}
	encryptionLogger.Debug("Decryption successful")
	return result, nil
}

// ExtractMetadata parses metadata from ciphertext.
// For legacy ciphertexts without metadata header it returns FormatVersion=1 and zero CreatedAt.
func ExtractMetadata(ciphertext string) (CipherMetadata, error) {
	if len(ciphertext) == 0 {
		return CipherMetadata{}, errors.New("ciphertext cannot be empty")
	}

	base64Payload, envelopeMeta, err := parseVisibleCipherEnvelope(ciphertext)
	if err != nil {
		return CipherMetadata{}, err
	}

	decoded, err := base64.StdEncoding.DecodeString(base64Payload)
	if err != nil {
		return CipherMetadata{}, fmt.Errorf("failed to decode base64: %w", err)
	}

	algorithmByte, _, _, _, _, _, meta, err := parseCipherPayload(decoded)
	if err != nil {
		return CipherMetadata{}, err
	}

	// Envelope metadata is visible and should be reflected in API output.
	if envelopeMeta != nil {
		if meta.FormatVersion < envelopeMeta.FormatVersion {
			meta.FormatVersion = envelopeMeta.FormatVersion
		}
		if meta.CreatedAt.IsZero() {
			meta.CreatedAt = envelopeMeta.CreatedAt
		}
		if meta.Algorithm == "" {
			meta.Algorithm = envelopeMeta.Algorithm
		}
	}

	if meta.Algorithm == "" {
		if algo, mapErr := indicatorToAlgorithm(algorithmByte); mapErr == nil {
			meta.Algorithm = algo
		}
	}

	return meta, nil
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
	encryptionLogger.Debug("Starting compression")

	var buf bytes.Buffer

	// Create a gzip writer with best compression
	gzw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		encryptionLogger.Debug("Failed to create gzip writer", zap.Error(err))
		return nil, fmt.Errorf("failed to create gzip writer: %w", err)
	}

	// Write data to the gzip writer
	if _, err := gzw.Write(data); err != nil {
		encryptionLogger.Debug("Failed to write data to gzip writer", zap.Error(err))
		_ = gzw.Close()
		return nil, fmt.Errorf("failed to write to gzip writer: %w", err)
	}

	// Close the gzip writer to flush any pending data
	if err := gzw.Close(); err != nil {
		encryptionLogger.Debug("Failed to close gzip writer", zap.Error(err))
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Get the compressed data
	compressed := buf.Bytes()
	encryptionLogger.Debug("Compression completed")

	return compressed, nil
}

// decompress decompresses gzipped data
func decompress(compressedData []byte) ([]byte, error) {
	encryptionLogger.Debug("Starting decompression")

	// Create a reader for the compressed data
	buf := bytes.NewBuffer(compressedData)
	gz, err := gzip.NewReader(buf)
	if err != nil {
		encryptionLogger.Debug("Failed to create gzip reader", zap.Error(err))
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gz.Close(); err != nil {
			encryptionLogger.Debug("Failed to close gzip reader", zap.Error(err))
		}
	}()

	// Read the decompressed data
	decompressed, err := io.ReadAll(gz)
	if err != nil {
		encryptionLogger.Debug("Failed to read decompressed data", zap.Error(err))
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	encryptionLogger.Debug("Decompression completed")
	return decompressed, nil
}

// SetDefaultAlgorithm sets the default key derivation algorithm
func SetDefaultAlgorithm(algorithm KeyDerivationAlgorithm) {
	if !isSupportedKeyDerivationAlgorithm(algorithm) {
		encryptionLogger.Debug("Ignoring unsupported algorithm", zap.String("algorithm", string(algorithm)))
		return
	}

	defaultAlgorithmMu.Lock()
	defer defaultAlgorithmMu.Unlock()
	defaultKeyDerivationAlgorithm = algorithm
	encryptionLogger.Debug("Default algorithm set", zap.String("algorithm", string(algorithm)))
}

func getDefaultAlgorithm() KeyDerivationAlgorithm {
	defaultAlgorithmMu.RLock()
	defer defaultAlgorithmMu.RUnlock()
	return defaultKeyDerivationAlgorithm
}

// GetDefaultAlgorithm returns the current default key derivation algorithm.
func GetDefaultAlgorithm() KeyDerivationAlgorithm {
	return getDefaultAlgorithm()
}

func isSupportedKeyDerivationAlgorithm(algorithm KeyDerivationAlgorithm) bool {
	switch algorithm {
	case Argon2idAlgorithm, PBKDF2SHA256Algorithm, PBKDF2SHA512Algorithm:
		return true
	default:
		return false
	}
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
	encryptionLogger.Debug("Computing HMAC")

	// Create secure buffer for the key
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		encryptionLogger.Debug("Failed to create secure buffer for key")
		return nil
	}
	defer keyBuf.Destroy()
	encryptionLogger.Debug("Created secure buffer for key")

	// Create HMAC with key from secure buffer
	h := hmac.New(sha256.New, keyBuf.Bytes())

	// Write data directly to HMAC (not using secure buffer for data)
	h.Write(data)

	// Add algorithm byte to HMAC
	if len(algorithm) > 0 {
		alg := algorithm[0]
		encryptionLogger.Debug("Including algorithm byte in HMAC calculation", zap.Any("algorithm", alg))
		h.Write([]byte{alg})
	}

	hmacValue := h.Sum(nil)
	encryptionLogger.Debug("HMAC calculation complete")
	return hmacValue
}

var errAuthenticationFailed = errors.New("cipher: message authentication failed")

func parseCipherPayload(decoded []byte) (algorithmByte byte, salt, nonce, encryptedData, hmacData, hmacValue []byte, meta CipherMetadata, err error) {
	const legacyHeaderLength = AlgorithmIndicatorLength + saltSize + nonceSize
	const minLegacyLength = legacyHeaderLength + hmacSize
	const minV2Length = headerV2Length + saltSize + nonceSize + hmacSize

	if len(decoded) < minLegacyLength {
		return 0, nil, nil, nil, nil, nil, CipherMetadata{}, errors.New("invalid ciphertext: too short")
	}

	offset := 0
	meta = CipherMetadata{FormatVersion: 1}

	if len(decoded) >= minV2Length && string(decoded[:headerMagicLength]) == headerMagicPrefix {
		version := int(decoded[headerMagicLength])
		if version != headerV2Version {
			return 0, nil, nil, nil, nil, nil, CipherMetadata{}, fmt.Errorf("invalid ciphertext: unsupported format version %d", version)
		}

		timestampRaw := decoded[headerMagicLength+headerVersionLength : headerMagicLength+headerVersionLength+headerTimestampLength]
		createdAtUnix, parseErr := strconv.ParseInt(string(timestampRaw), 10, 64)
		if parseErr != nil {
			return 0, nil, nil, nil, nil, nil, CipherMetadata{}, fmt.Errorf("invalid ciphertext: malformed timestamp metadata")
		}
		meta = CipherMetadata{
			FormatVersion: version,
			CreatedAt:     time.Unix(createdAtUnix, 0).UTC(),
		}

		offset = headerV2Length - AlgorithmIndicatorLength
	}

	algorithmByte = decoded[offset]
	if algo, mapErr := indicatorToAlgorithm(algorithmByte); mapErr == nil {
		meta.Algorithm = algo
	}
	start := offset + AlgorithmIndicatorLength
	if len(decoded) < start+saltSize+nonceSize+hmacSize {
		return 0, nil, nil, nil, nil, nil, CipherMetadata{}, errors.New("invalid ciphertext: too short")
	}

	salt = decoded[start : start+saltSize]
	nonce = decoded[start+saltSize : start+saltSize+nonceSize]
	encryptedData = decoded[start+saltSize+nonceSize : len(decoded)-hmacSize]
	hmacValue = decoded[len(decoded)-hmacSize:]
	hmacData = decoded[:len(decoded)-hmacSize]
	return algorithmByte, salt, nonce, encryptedData, hmacData, hmacValue, meta, nil
}

func decryptWithAlgorithm(password string, algo KeyDerivationAlgorithm, algorithmByte byte, salt, nonce, encryptedData, hmacData, hmacValue []byte) (string, error) {
	encryptionLogger.Debug("Trying algorithm", zap.String("algorithm", string(algo)))

	key, err := deriveKey(password, salt, algo)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %w", err)
	}
	defer func() {
		memguard.WipeBytes(key)
		encryptionLogger.Debug("Wiped original key from memory")
	}()

	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		return "", fmt.Errorf("failed to create secure buffer for key")
	}
	defer keyBuf.Destroy()

	expectedHMAC := computeHMAC(key, hmacData, algorithmByte)
	if !hmac.Equal(expectedHMAC, hmacValue) {
		return "", errAuthenticationFailed
	}

	block, err := aes.NewCipher(keyBuf.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	decryptedData, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	decompressedData, err := decompress(decryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decompress data: %w", err)
	}

	return string(decompressedData), nil
}

func resolveDecryptionAlgorithms(algorithmByte byte, explicit ...KeyDerivationAlgorithm) ([]KeyDerivationAlgorithm, error) {
	if len(explicit) > 0 && explicit[0] != "" {
		return []KeyDerivationAlgorithm{explicit[0]}, nil
	}

	switch algorithmByte {
	case Argon2idIndicator, legacyArgon2Indicator:
		return []KeyDerivationAlgorithm{Argon2idAlgorithm}, nil
	case PBKDF2SHA256Indicator:
		return []KeyDerivationAlgorithm{PBKDF2SHA256Algorithm}, nil
	case PBKDF2SHA512Indicator:
		return []KeyDerivationAlgorithm{PBKDF2SHA512Algorithm}, nil
	case legacyPBKDF2Indicator:
		// Legacy format could not distinguish PBKDF2 variants; try both.
		return []KeyDerivationAlgorithm{PBKDF2SHA256Algorithm, PBKDF2SHA512Algorithm}, nil
	default:
		return nil, fmt.Errorf("invalid ciphertext: unknown algorithm indicator 0x%x", algorithmByte)
	}
}

func indicatorToAlgorithm(indicator byte) (KeyDerivationAlgorithm, error) {
	switch indicator {
	case Argon2idIndicator, legacyArgon2Indicator:
		return Argon2idAlgorithm, nil
	case PBKDF2SHA256Indicator:
		return PBKDF2SHA256Algorithm, nil
	case PBKDF2SHA512Indicator:
		return PBKDF2SHA512Algorithm, nil
	case legacyPBKDF2Indicator:
		// Legacy marker cannot distinguish SHA-256/SHA-512.
		return "", fmt.Errorf("ambiguous legacy pbkdf2 algorithm indicator")
	default:
		return "", fmt.Errorf("invalid ciphertext: unknown algorithm indicator 0x%x", indicator)
	}
}

func buildVisibleCipherEnvelope(base64Payload string, algorithm KeyDerivationAlgorithm, createdAt time.Time) string {
	return fmt.Sprintf("%s;ts=%d;alg=%s;%s", visibleEnvelopeVersion, createdAt.Unix(), algorithm, base64Payload)
}

func parseVisibleCipherEnvelope(ciphertext string) (string, *CipherMetadata, error) {
	if !strings.HasPrefix(ciphertext, visibleEnvelopePrefix) {
		return ciphertext, nil, nil
	}

	parts := strings.SplitN(ciphertext, ";", 4)
	if len(parts) != 4 {
		return "", nil, errors.New("invalid ciphertext envelope: malformed structure")
	}
	if parts[0] != visibleEnvelopeVersion {
		return "", nil, fmt.Errorf("invalid ciphertext envelope: unsupported version %q", parts[0])
	}
	if !strings.HasPrefix(parts[1], "ts=") {
		return "", nil, errors.New("invalid ciphertext envelope: missing ts field")
	}
	if !strings.HasPrefix(parts[2], "alg=") {
		return "", nil, errors.New("invalid ciphertext envelope: missing alg field")
	}

	tsRaw := strings.TrimPrefix(parts[1], "ts=")
	createdAtUnix, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return "", nil, errors.New("invalid ciphertext envelope: malformed ts field")
	}

	algoRaw := strings.TrimPrefix(parts[2], "alg=")
	algo, err := ValidateAlgorithm(algoRaw)
	if err != nil {
		return "", nil, fmt.Errorf("invalid ciphertext envelope: invalid alg field: %w", err)
	}

	base64Payload := parts[3]
	if base64Payload == "" {
		return "", nil, errors.New("invalid ciphertext envelope: empty payload")
	}

	meta := &CipherMetadata{
		FormatVersion: headerV2Version,
		CreatedAt:     time.Unix(createdAtUnix, 0).UTC(),
		Algorithm:     algo,
	}
	return base64Payload, meta, nil
}

func algorithmToIndicator(algo KeyDerivationAlgorithm) (byte, error) {
	switch algo {
	case Argon2idAlgorithm:
		return Argon2idIndicator, nil
	case PBKDF2SHA256Algorithm:
		return PBKDF2SHA256Indicator, nil
	case PBKDF2SHA512Algorithm:
		return PBKDF2SHA512Indicator, nil
	default:
		return 0, fmt.Errorf("unsupported key derivation algorithm: %s", algo)
	}
}

// deriveKey derives an encryption key from password and salt using the specified algorithm
func deriveKey(password string, salt []byte, algorithm KeyDerivationAlgorithm) ([]byte, error) {
	encryptionLogger.Debug("Starting key derivation", zap.String("algorithm", string(algorithm)))

	var key []byte
	var err error

	switch algorithm {
	case PBKDF2SHA512Algorithm:
		encryptionLogger.Debug("Using PBKDF2-SHA512")
		key = pbkdf2.Key([]byte(password), salt, pbkdf2SHA512Iterations, keySize, sha512.New)
		encryptionLogger.Debug("PBKDF2-SHA512 completed")
	case PBKDF2SHA256Algorithm:
		encryptionLogger.Debug("Using PBKDF2-SHA256")
		key = pbkdf2.Key([]byte(password), salt, pbkdf2SHA256Iterations, keySize, sha256.New)
		encryptionLogger.Debug("PBKDF2-SHA256 completed")
	case Argon2idAlgorithm:
		encryptionLogger.Debug("Using Argon2id")
		key = argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Threads, keySize)
		encryptionLogger.Debug("Argon2id completed")
	default:
		encryptionLogger.Debug("Unknown algorithm", zap.String("algorithm", string(algorithm)))
		return nil, fmt.Errorf("unsupported key derivation algorithm: %s", algorithm)
	}

	if err != nil {
		encryptionLogger.Debug("Key derivation error", zap.Error(err))
		return nil, err
	}

	encryptionLogger.Debug("Key derivation successful")
	return key, nil
}
