package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

// Kerberos AES encryption type constants.
const (
	EtypeAES128 = 17
	EtypeAES256 = 18

	// Key sizes in bytes
	AES128KeySize = 16
	AES256KeySize = 32

	// PBKDF2 iterations per RFC 3962
	PBKDF2Iterations = 4096
)

// EncryptAES encrypts data using AES-CTS-HMAC-SHA1 (etypes 17/18).
//
// EDUCATIONAL: AES Encryption in Kerberos
//
// AES encryption in Kerberos uses:
//   - AES in CBC mode with CipherText Stealing (CTS)
//   - HMAC-SHA1-96 for integrity (truncated to 12 bytes)
//   - Random 16-byte confounder
//
// The process:
//  1. Generate 16-byte random confounder
//  2. Derive encryption key Ke and integrity key Ki from base key
//  3. Encrypt: AES-CBC-CTS(Ke, confounder || plaintext)
//  4. Compute checksum: HMAC-SHA1-96(Ki, ciphertext)
//  5. Return: ciphertext || checksum
//
// CTS (Cipher Text Stealing) allows encrypting data that isn't a
// multiple of the block size without padding, which is important
// for Kerberos message formats.
func EncryptAES(key, plaintext []byte, usage int, etype int) ([]byte, error) {
	keySize := AES128KeySize
	if etype == EtypeAES256 {
		keySize = AES256KeySize
	}
	if len(key) != keySize {
		return nil, errors.New("invalid key size for AES etype")
	}

	// Generate 16-byte confounder
	confounder := make([]byte, 16)
	if _, err := rand.Read(confounder); err != nil {
		return nil, err
	}

	// Derive Ke (encryption) and Ki (integrity) keys
	ke := deriveAESKey(key, usage, "enc", keySize)
	ki := deriveAESKey(key, usage, "int", keySize)

	// Data to encrypt: confounder || plaintext
	dataToEncrypt := append(confounder, plaintext...)

	// Encrypt with AES-CBC-CTS
	ciphertext, err := aesCBCCTSEncrypt(ke, dataToEncrypt)
	if err != nil {
		return nil, err
	}

	// Compute HMAC-SHA1-96 checksum
	h := hmac.New(sha1.New, ki)
	h.Write(ciphertext)
	checksum := h.Sum(nil)[:12] // Truncate to 96 bits

	// Return ciphertext || checksum
	return append(ciphertext, checksum...), nil
}

// DecryptAES decrypts data encrypted with AES-CTS-HMAC-SHA1.
//
// EDUCATIONAL: AES Decryption in Kerberos
//
// Reverses the encryption:
//  1. Split input into ciphertext and checksum (last 12 bytes)
//  2. Derive Ke and Ki from base key
//  3. Verify HMAC-SHA1-96 checksum
//  4. Decrypt with AES-CBC-CTS
//  5. Strip 16-byte confounder
func DecryptAES(key, ciphertext []byte, usage int, etype int) ([]byte, error) {
	keySize := AES128KeySize
	if etype == EtypeAES256 {
		keySize = AES256KeySize
	}
	if len(key) != keySize {
		return nil, errors.New("invalid key size for AES etype")
	}
	if len(ciphertext) < 28 { // 16-byte confounder + 12-byte checksum minimum
		return nil, errors.New("ciphertext too short")
	}

	// Split into encrypted data and checksum
	checksumOffset := len(ciphertext) - 12
	encData := ciphertext[:checksumOffset]
	checksum := ciphertext[checksumOffset:]

	// Derive keys
	ke := deriveAESKey(key, usage, "enc", keySize)
	ki := deriveAESKey(key, usage, "int", keySize)

	// Verify checksum
	h := hmac.New(sha1.New, ki)
	h.Write(encData)
	expectedChecksum := h.Sum(nil)[:12]
	if !hmac.Equal(checksum, expectedChecksum) {
		return nil, errors.New("checksum verification failed")
	}

	// Decrypt
	decrypted, err := aesCBCCTSDecrypt(ke, encData)
	if err != nil {
		return nil, err
	}

	// Strip 16-byte confounder
	if len(decrypted) < 16 {
		return nil, errors.New("decrypted data too short")
	}
	return decrypted[16:], nil
}

// deriveAESKey derives a subkey from the base key using the Kerberos
// key derivation function (RFC 3961).
//
// EDUCATIONAL: AES Key Derivation
//
// Kerberos derives separate keys for encryption (Ke) and integrity (Ki)
// from a single base key. This is done using:
//
//	dk(key, constant) = random-to-key(DR(key, constant))
//	DR(key, constant) = k-truncate(E(key, constant, initial-cipher-state))
//
// The constant includes the key usage number, ensuring different keys
// for different message types (preventing cut-and-paste attacks).
func deriveAESKey(baseKey []byte, usage int, derivation string, keySize int) []byte {
	// Build the constant: usage (4 bytes big-endian) + derivation type
	constant := make([]byte, 5)
	binary.BigEndian.PutUint32(constant[:4], uint32(usage))
	switch derivation {
	case "enc":
		constant[4] = 0xAA
	case "int":
		constant[4] = 0x55
	case "chk":
		constant[4] = 0x99
	}

	// Use the DK function from RFC 3961
	return dk(baseKey, constant, keySize)
}

// dk implements the DK (Derive Key) function from RFC 3961.
func dk(key, constant []byte, keySize int) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// n-fold the constant to block size
	nfolded := nfold(constant, block.BlockSize())

	// Generate enough key material
	var keyMaterial []byte
	for len(keyMaterial) < keySize {
		block.Encrypt(nfolded, nfolded)
		keyMaterial = append(keyMaterial, nfolded...)
	}

	return keyMaterial[:keySize]
}

// nfold performs the n-fold operation from RFC 3961.
// This spreads the entropy of the input across the output length.
func nfold(input []byte, outLen int) []byte {
	inBits := len(input) * 8
	outBits := outLen * 8

	// Find LCM of input and output lengths
	lcm := (inBits * outBits) / gcd(inBits, outBits)

	result := make([]byte, outLen)
	for i := lcm/outBits - 1; i >= 0; i-- {
		// Rotate and add
		tmp := rotateRight(input, i*inBits%outBits)
		result = addBytes(result, tmp)
	}
	return result
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func rotateRight(data []byte, bits int) []byte {
	result := make([]byte, len(data))
	bytes := bits / 8
	bitOffset := bits % 8

	for i := 0; i < len(data); i++ {
		srcIdx := (i + bytes) % len(data)
		nextIdx := (srcIdx + 1) % len(data)
		result[i] = (data[srcIdx] >> bitOffset) | (data[nextIdx] << (8 - bitOffset))
	}
	return result
}

func addBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	carry := 0
	for i := len(a) - 1; i >= 0; i-- {
		sum := int(a[i]) + int(b[i%len(b)]) + carry
		result[i] = byte(sum & 0xff)
		carry = sum >> 8
	}
	// Handle final carry by adding 1 to result
	if carry > 0 {
		for i := len(result) - 1; i >= 0 && carry > 0; i-- {
			sum := int(result[i]) + carry
			result[i] = byte(sum & 0xff)
			carry = sum >> 8
		}
	}
	return result
}

// aesCBCCTSEncrypt performs AES-CBC encryption with CipherText Stealing.
func aesCBCCTSEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	// Pad to at least one block
	if len(plaintext) < blockSize {
		// For less than one block, just use CBC with zero padding
		padded := make([]byte, blockSize)
		copy(padded, plaintext)
		plaintext = padded
	}

	// If exactly one block, standard CBC
	if len(plaintext) == blockSize {
		iv := make([]byte, blockSize)
		mode := cipher.NewCBCEncrypter(block, iv)
		ciphertext := make([]byte, len(plaintext))
		mode.CryptBlocks(ciphertext, plaintext)
		return ciphertext, nil
	}

	// CTS mode for multiple blocks
	// Pad the last block if needed
	remainder := len(plaintext) % blockSize
	if remainder != 0 {
		padding := make([]byte, blockSize-remainder)
		plaintext = append(plaintext, padding...)
	}

	iv := make([]byte, blockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// CTS: swap last two blocks
	if len(ciphertext) >= 2*blockSize {
		lastBlockStart := len(ciphertext) - blockSize
		secondLastStart := lastBlockStart - blockSize
		copy(ciphertext[secondLastStart:], ciphertext[lastBlockStart:])
		copy(ciphertext[lastBlockStart:], ciphertext[secondLastStart:lastBlockStart])
	}

	// Trim to original length if padded
	if remainder != 0 {
		ciphertext = ciphertext[:len(plaintext)-blockSize+remainder]
	}

	return ciphertext, nil
}

// aesCBCCTSDecrypt performs AES-CBC decryption with CipherText Stealing.
func aesCBCCTSDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(ciphertext) < blockSize {
		return nil, errors.New("ciphertext too short")
	}

	// If exactly one block, standard CBC
	if len(ciphertext) == blockSize {
		iv := make([]byte, blockSize)
		mode := cipher.NewCBCDecrypter(block, iv)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)
		return plaintext, nil
	}

	// CTS mode - need to unswap and pad
	remainder := len(ciphertext) % blockSize
	if remainder != 0 {
		// Pad the ciphertext
		padding := make([]byte, blockSize-remainder)
		ciphertext = append(ciphertext, padding...)
	}

	// Reverse the CTS swap
	if len(ciphertext) >= 2*blockSize {
		lastBlockStart := len(ciphertext) - blockSize
		secondLastStart := lastBlockStart - blockSize
		tmp := make([]byte, blockSize)
		copy(tmp, ciphertext[lastBlockStart:])
		copy(ciphertext[lastBlockStart:], ciphertext[secondLastStart:lastBlockStart])
		copy(ciphertext[secondLastStart:], tmp)
	}

	iv := make([]byte, blockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Trim padding
	if remainder != 0 {
		plaintext = plaintext[:len(plaintext)-blockSize+remainder]
	}

	return plaintext, nil
}

// AES128Key derives an AES128 key from a password and salt.
//
// EDUCATIONAL: AES Key Derivation from Password
//
// Unlike RC4 where the key IS the NTLM hash, AES keys must be derived
// using PBKDF2:
//
//	key = PBKDF2-HMAC-SHA1(password, salt, 4096, keysize)
//	salt = uppercase(REALM) + principalname
//
// For user "jsmith" in realm "CORP.LOCAL":
//
//	salt = "CORP.LOCALjsmith"
//
// This makes AES keys password-specific AND realm-specific, unlike RC4.
func AES128Key(password, salt string) []byte {
	return pbkdf2.Key([]byte(password), []byte(salt), PBKDF2Iterations, AES128KeySize, sha1.New)
}

// AES256Key derives an AES256 key from a password and salt.
func AES256Key(password, salt string) []byte {
	return pbkdf2.Key([]byte(password), []byte(salt), PBKDF2Iterations, AES256KeySize, sha1.New)
}

// BuildAESSalt constructs the salt for AES key derivation.
//
// EDUCATIONAL: AES Salt Construction
//
// The salt is constructed as:
//
//	salt = uppercase(realm) + principalname
//
// For user principals:
//
//	salt = "CORP.LOCAL" + "jsmith"
//
// For service principals:
//
//	salt = "CORP.LOCAL" + "HOST" + "server.corp.local"
//
// Note: The realm is uppercase but the principal components are NOT.
func BuildAESSalt(realm, principal string) string {
	// For user principals: REALM + username
	// For service principals: REALM + service + hostname
	// TODO: Handle service principals with multiple components
	return realm + principal
}

// HMACSHA1AES256 computes the HMAC-SHA1-96 checksum for AES256.
//
// EDUCATIONAL: PAC Checksums
//
// PAC signatures use HMAC with a derived key:
//   - Type 16 (HMAC-SHA1-96-AES256): 12-byte truncated HMAC-SHA1
//   - The key is derived using the checksum key derivation constant
//
// The checksum provides integrity AND authenticity since only
// the KDC or service knowing the key can produce a valid signature.
func HMACSHA1AES256(key, data []byte) ([]byte, error) {
	// Derive the checksum key (Ki) using key usage for PAC
	checksumKey := deriveAESKey(key, 17, "kerberos", AES256KeySize) // Key usage 17 = PAC

	h := hmac.New(sha1.New, checksumKey)
	h.Write(data)
	sig := h.Sum(nil)

	// Truncate to 12 bytes (96 bits) for HMAC-SHA1-96
	return sig[:12], nil
}

// HMACSHA1AES128 computes the HMAC-SHA1-96 checksum for AES128.
func HMACSHA1AES128(key, data []byte) ([]byte, error) {
	checksumKey := deriveAESKey(key, 17, "kerberos", AES128KeySize)

	h := hmac.New(sha1.New, checksumKey)
	h.Write(data)
	sig := h.Sum(nil)

	return sig[:12], nil
}

// HMACMD5 computes the HMAC-MD5 checksum for RC4 encryption.
//
// EDUCATIONAL: RC4-HMAC Checksum
//
// RC4-HMAC uses HMAC-MD5 for checksums:
//   - Type -138 (HMAC-MD5 for RC4)
//   - Full 16-byte output (not truncated)
//
// This is weaker than AES checksums but still provides integrity.
func HMACMD5(key, data []byte) ([]byte, error) {
	// For RC4, the checksum key is the session key modified by key usage
	// HMAC-MD5(Ksign, "signaturekey" || 0x00) then HMAC-MD5 of data

	// Derive Ksign
	signKey := deriveRC4SignKey(key)

	h := hmac.New(md5.New, signKey)
	h.Write(data)
	return h.Sum(nil), nil
}

func deriveRC4SignKey(key []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write([]byte("signaturekey\x00"))
	return h.Sum(nil)
}
