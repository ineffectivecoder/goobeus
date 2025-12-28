package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// Kerberos encryption type constants.
const (
	EtypeRC4HMAC = 23
)

// EncryptRC4 encrypts data using RC4-HMAC-MD5 (etype 23).
//
// EDUCATIONAL: RC4-HMAC Encryption Process
//
// This is the most common encryption type in Kerberos because the key
// is literally the NTLM hash, enabling pass-the-hash attacks.
//
// The encryption process (RFC 4757):
//
//  1. Generate 8-byte random confounder
//  2. Compute Ks = HMAC-MD5(key, usage_number_as_le32)
//  3. Compute checksum = HMAC-MD5(Ks, confounder || plaintext)
//  4. Compute Ke = HMAC-MD5(Ks, checksum)
//  5. Encrypt data with RC4: ciphertext = RC4(Ke, confounder || plaintext)
//  6. Return checksum || ciphertext
//
// Parameters:
//   - key: The encryption key (NTLM hash for RC4-HMAC)
//   - plaintext: Data to encrypt
//   - usage: Key usage number (e.g., 3 for AS-REP encrypted part)
//
// Returns:
//   - Encrypted data: 16-byte checksum + encrypted(confounder + plaintext)
func EncryptRC4(key, plaintext []byte, usage int) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("RC4 key must be 16 bytes (NTLM hash)")
	}

	// Step 1: Generate 8-byte confounder (random nonce)
	confounder := make([]byte, 8)
	if _, err := rand.Read(confounder); err != nil {
		return nil, err
	}

	// Step 2: Derive Ks from key and usage
	// Ks = HMAC-MD5(key, usage_as_le32)
	ks := deriveKs(key, usage)

	// Data to encrypt: confounder || plaintext
	dataToEncrypt := append(confounder, plaintext...)

	// Step 3: Compute checksum
	// checksum = HMAC-MD5(Ks, data_to_encrypt)
	checksumHmac := hmac.New(md5.New, ks)
	checksumHmac.Write(dataToEncrypt)
	checksum := checksumHmac.Sum(nil)

	// Step 4: Derive Ke from Ks and checksum
	// Ke = HMAC-MD5(Ks, checksum)
	keHmac := hmac.New(md5.New, ks)
	keHmac.Write(checksum)
	ke := keHmac.Sum(nil)

	// Step 5: RC4 encrypt
	cipher, err := rc4.NewCipher(ke)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(dataToEncrypt))
	cipher.XORKeyStream(ciphertext, dataToEncrypt)

	// Step 6: Return checksum || ciphertext
	return append(checksum, ciphertext...), nil
}

// DecryptRC4 decrypts data encrypted with RC4-HMAC-MD5.
//
// EDUCATIONAL: RC4-HMAC Decryption Process
//
// This reverses the encryption:
//  1. Split input into checksum (first 16 bytes) and ciphertext
//  2. Derive Ks from key and usage
//  3. Derive Ke from Ks and checksum
//  4. RC4 decrypt to get confounder || plaintext
//  5. Verify checksum
//  6. Return plaintext (strip 8-byte confounder)
func DecryptRC4(key, ciphertext []byte, usage int) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("RC4 key must be 16 bytes (NTLM hash)")
	}
	if len(ciphertext) < 24 { // 16-byte checksum + 8-byte confounder minimum
		return nil, errors.New("ciphertext too short")
	}

	// Split into checksum and encrypted data
	checksum := ciphertext[:16]
	encryptedData := ciphertext[16:]

	// Derive Ks
	ks := deriveKs(key, usage)

	// Derive Ke from checksum
	keHmac := hmac.New(md5.New, ks)
	keHmac.Write(checksum)
	ke := keHmac.Sum(nil)

	// RC4 decrypt
	cipher, err := rc4.NewCipher(ke)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(encryptedData))
	cipher.XORKeyStream(decrypted, encryptedData)

	// Verify checksum
	verifyHmac := hmac.New(md5.New, ks)
	verifyHmac.Write(decrypted)
	expectedChecksum := verifyHmac.Sum(nil)

	if !hmac.Equal(checksum, expectedChecksum) {
		return nil, errors.New("checksum verification failed")
	}

	// Strip 8-byte confounder
	return decrypted[8:], nil
}

// deriveKs derives the signing key Ks from the base key and usage number.
func deriveKs(key []byte, usage int) []byte {
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, uint32(usage))

	h := hmac.New(md5.New, key)
	h.Write(usageBytes)
	return h.Sum(nil)
}

// RC4Key computes an RC4 key from an NTLM hash.
//
// EDUCATIONAL: For RC4-HMAC, the key IS the NTLM hash
//
// This is why pass-the-hash works: if you have someone's NTLM hash,
// you can directly use it as the Kerberos RC4 key without knowing
// the plaintext password.
func RC4Key(ntlmHash []byte) []byte {
	if len(ntlmHash) != 16 {
		return nil
	}
	return ntlmHash
}

// NTLMHash computes the NTLM hash from a password.
//
// EDUCATIONAL: NTLM Hash Computation
//
// The NTLM hash is simply MD4(UTF16-LE(password)).
// This hash IS the RC4-HMAC key for Kerberos.
//
// Example:
//
//	Password: "Password1"
//	UTF-16LE: P\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x001\x00
//	MD4 hash: 64f12cddaa88057e06a81b54e73b949b
//
// This is why you can request TGTs with just the hash!
func NTLMHash(password string) []byte {
	// Convert to UTF-16LE
	utf16le := utf16.Encode([]rune(password))
	passwordBytes := make([]byte, len(utf16le)*2)
	for i, r := range utf16le {
		binary.LittleEndian.PutUint16(passwordBytes[i*2:], r)
	}

	// MD4 hash
	return md4Hash(passwordBytes)
}

// md4Hash computes MD4 hash (used for NTLM).
// Implementing MD4 here since it's not in Go's crypto package.
func md4Hash(data []byte) []byte {
	// MD4 constants
	var (
		a0 uint32 = 0x67452301
		b0 uint32 = 0xefcdab89
		c0 uint32 = 0x98badcfe
		d0 uint32 = 0x10325476
	)

	// Pre-processing: adding padding bits
	origLen := len(data)
	data = append(data, 0x80)
	for (len(data)+8)%64 != 0 {
		data = append(data, 0x00)
	}

	// Append original length in bits as 64-bit little-endian
	lenBits := uint64(origLen) * 8
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, lenBits)
	data = append(data, lenBytes...)

	// Process each 64-byte chunk
	for i := 0; i < len(data); i += 64 {
		chunk := data[i : i+64]
		var m [16]uint32
		for j := 0; j < 16; j++ {
			m[j] = binary.LittleEndian.Uint32(chunk[j*4:])
		}

		a, b, c, d := a0, b0, c0, d0

		// Round 1
		for _, k := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
			s := []uint32{3, 7, 11, 19}[k%4]
			f := (b & c) | (^b & d)
			a, d, c, b = d, c, b, rotl32(a+f+m[k], s)
		}

		// Round 2
		for _, k := range []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15} {
			s := []uint32{3, 5, 9, 13}[k%4]
			f := (b & c) | (b & d) | (c & d)
			a, d, c, b = d, c, b, rotl32(a+f+m[k]+0x5a827999, s)
		}

		// Round 3
		for _, k := range []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15} {
			s := []uint32{3, 9, 11, 15}[k%4]
			f := b ^ c ^ d
			a, d, c, b = d, c, b, rotl32(a+f+m[k]+0x6ed9eba1, s)
		}

		a0 += a
		b0 += b
		c0 += c
		d0 += d
	}

	// Produce final hash value (little-endian)
	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:], a0)
	binary.LittleEndian.PutUint32(result[4:], b0)
	binary.LittleEndian.PutUint32(result[8:], c0)
	binary.LittleEndian.PutUint32(result[12:], d0)

	return result
}

func rotl32(x uint32, n uint32) uint32 {
	return (x << n) | (x >> (32 - n))
}
