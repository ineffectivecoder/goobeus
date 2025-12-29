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

	// Compute HMAC-SHA1-96 checksum on PLAINTEXT (per RFC 3962)
	// IMPORTANT: Kerberos HMAC is computed on confounder || plaintext, NOT on ciphertext!
	h := hmac.New(sha1.New, ki)
	h.Write(dataToEncrypt)      // NOT ciphertext!
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
//  3. Decrypt with AES-CBC-CTS
//  4. Verify HMAC-SHA1-96 checksum on DECRYPTED plaintext (per RFC 3962)
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

	// Decrypt FIRST (must decrypt before verifying HMAC per RFC 3962)
	decrypted, err := aesCBCCTSDecrypt(ke, encData)
	if err != nil {
		return nil, err
	}

	// Verify HMAC on DECRYPTED plaintext (confounder + data), NOT ciphertext
	// RFC 3962: HMAC is computed on plaintext before encryption
	h := hmac.New(sha1.New, ki)
	h.Write(decrypted) // IMPORTANT: HMAC on decrypted data!
	expectedChecksum := h.Sum(nil)[:12]
	if !hmac.Equal(checksum, expectedChecksum) {
		return nil, errors.New("checksum verification failed")
	}

	// Strip 16-byte confounder
	if len(decrypted) < 16 {
		return nil, errors.New("decrypted data too short")
	}
	return decrypted[16:], nil
}

// DecryptAESNoChecksum decrypts data encrypted with AES-CTS-HMAC-SHA1, skipping checksum verification.
// ONLY USE FOR DEBUGGING - this bypasses integrity verification!
func DecryptAESNoChecksum(key, ciphertext []byte, usage int, etype int) ([]byte, error) {
	keySize := AES128KeySize
	if etype == EtypeAES256 {
		keySize = AES256KeySize
	}
	if len(key) != keySize {
		return nil, errors.New("invalid key size for AES etype")
	}
	if len(ciphertext) < 28 {
		return nil, errors.New("ciphertext too short")
	}

	// Split into encrypted data and checksum
	checksumOffset := len(ciphertext) - 12
	encData := ciphertext[:checksumOffset]

	// Derive encryption key only
	ke := deriveAESKey(key, usage, "enc", keySize)

	// Decrypt without checksum verification
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
// Implementation based on RFC 3961 and verified against gokrb5.
func nfold(input []byte, outLen int) []byte {
	k := len(input) * 8 // input length in bits
	n := outLen * 8     // output length in bits

	// Get the lowest common multiple of the two bit sizes
	lcmVal := lcm(n, k)
	replicate := lcmVal / k

	// Build the rotated and concatenated bytes
	var sumBytes []byte
	for i := 0; i < replicate; i++ {
		rotation := 13 * i // RFC 3961 specifies 13-bit rotation
		sumBytes = append(sumBytes, rotateRightBits(input, rotation)...)
	}

	// Now fold by adding n-bit chunks with ones-complement addition
	result := make([]byte, n/8)
	chunk := make([]byte, n/8)
	for i := 0; i < lcmVal/n; i++ {
		for j := 0; j < n/8; j++ {
			chunk[j] = sumBytes[j+(i*len(chunk))]
		}
		result = onesComplementAdd(result, chunk)
	}
	return result
}

// lcm returns least common multiple of x and y
func lcm(x, y int) int {
	return (x * y) / gcd(x, y)
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// rotateRightBits rotates byte slice right by step bits
func rotateRightBits(b []byte, step int) []byte {
	out := make([]byte, len(b))
	bitLen := len(b) * 8
	for i := 0; i < bitLen; i++ {
		v := getBit(b, i)
		setBit(out, (i+step)%bitLen, v)
	}
	return out
}

// getBit gets the bit at position p (0-indexed from left)
func getBit(b []byte, p int) int {
	pByte := p / 8
	pBit := uint(p % 8)
	return int((b[pByte] >> (7 - pBit)) & 0x01)
}

// setBit sets the bit at position p to value v
func setBit(b []byte, p, v int) {
	pByte := p / 8
	pBit := uint(p % 8)
	if v == 1 {
		b[pByte] |= byte(1 << (7 - pBit))
	}
}

// onesComplementAdd performs ones-complement addition of two byte slices
func onesComplementAdd(n1, n2 []byte) []byte {
	numBits := len(n1) * 8
	out := make([]byte, len(n1))
	carry := 0

	// Add from right to left (least significant bit first)
	for i := numBits - 1; i >= 0; i-- {
		n1b := getBit(n1, i)
		n2b := getBit(n2, i)
		s := n1b + n2b + carry

		if s == 0 || s == 1 {
			setBit(out, i, s)
			carry = 0
		} else if s == 2 {
			carry = 1
		} else if s == 3 {
			setBit(out, i, 1)
			carry = 1
		}
	}

	// Ones-complement: wrap carry around
	if carry == 1 {
		carryArray := make([]byte, len(n1))
		carryArray[len(carryArray)-1] = 1
		out = onesComplementAdd(out, carryArray)
	}
	return out
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

	// CTS: swap last two blocks (need temp buffer to avoid corruption)
	if len(ciphertext) >= 2*blockSize {
		lastBlockStart := len(ciphertext) - blockSize
		secondLastStart := lastBlockStart - blockSize
		// Save second-to-last block
		secondLastBlock := make([]byte, blockSize)
		copy(secondLastBlock, ciphertext[secondLastStart:lastBlockStart])
		// Move last block to second-to-last position
		copy(ciphertext[secondLastStart:], ciphertext[lastBlockStart:])
		// Move saved second-to-last to last position
		copy(ciphertext[lastBlockStart:], secondLastBlock)
	}

	// Trim to original length if padded
	if remainder != 0 {
		ciphertext = ciphertext[:len(plaintext)-blockSize+remainder]
	}

	return ciphertext, nil
}

// aesCBCCTSDecrypt performs AES-CBC decryption with CipherText Stealing.
// This implementation matches Impacket's basic_decrypt using ECB mode with manual XOR.
func aesCBCCTSDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(ciphertext) < blockSize {
		return nil, errors.New("ciphertext too short")
	}

	// If exactly one block, standard AES-ECB decrypt
	if len(ciphertext) == blockSize {
		plaintext := make([]byte, blockSize)
		block.Decrypt(plaintext, ciphertext)
		return plaintext, nil
	}

	// Split ciphertext into blocks (last block may be partial)
	numBlocks := (len(ciphertext) + blockSize - 1) / blockSize
	cblocks := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		cblocks[i] = make([]byte, end-start)
		copy(cblocks[i], ciphertext[start:end])
	}
	lastlen := len(cblocks[numBlocks-1])

	// CBC-decrypt all but the last two blocks
	prevCblock := make([]byte, blockSize)
	plaintext := make([]byte, 0, len(ciphertext))

	for i := 0; i < numBlocks-2; i++ {
		decrypted := make([]byte, blockSize)
		block.Decrypt(decrypted, cblocks[i])
		xorBytes(decrypted, decrypted, prevCblock)
		plaintext = append(plaintext, decrypted...)
		copy(prevCblock, cblocks[i])
	}

	// Decrypt the second-to-last cipher block
	// The left side of the decrypted block will be the final block of plaintext
	// xor'd with the final partial cipher block; the right side will be the omitted bytes
	bb := make([]byte, blockSize)
	block.Decrypt(bb, cblocks[numBlocks-2])

	// lastplaintext = bb[:lastlen] XOR cblocks[-1]
	lastplaintext := make([]byte, lastlen)
	for i := 0; i < lastlen; i++ {
		lastplaintext[i] = bb[i] ^ cblocks[numBlocks-1][i]
	}

	// omitted = bb[lastlen:]
	omitted := bb[lastlen:]

	// Decrypt the final cipher block plus the omitted bytes to get the second-to-last plaintext block
	finalCipherBlock := make([]byte, blockSize)
	copy(finalCipherBlock, cblocks[numBlocks-1])
	copy(finalCipherBlock[lastlen:], omitted)

	decrypted := make([]byte, blockSize)
	block.Decrypt(decrypted, finalCipherBlock)
	xorBytes(decrypted, decrypted, prevCblock)

	plaintext = append(plaintext, decrypted...)
	plaintext = append(plaintext, lastplaintext...)

	return plaintext, nil
}

// xorBytes XORs a and b into dst. All slices must be the same length.
func xorBytes(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
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
// AES128Key derives an AES128 key from a password and salt using RFC 3962 string-to-key.
func AES128Key(password, salt string) []byte {
	// Step 1: PBKDF2 to get seed
	seed := pbkdf2.Key([]byte(password), []byte(salt), PBKDF2Iterations, AES128KeySize, sha1.New)

	// Step 2: random-to-key is identity for AES
	tkey := seed

	// Step 3: DK derivation with constant "kerberos"
	return dk(tkey, []byte("kerberos"), AES128KeySize)
}

// AES256Key derives an AES256 key from a password and salt using RFC 3962 string-to-key.
//
// EDUCATIONAL: RFC 3962 String-to-Key
//
// The AES string-to-key function is NOT just PBKDF2! It's:
//  1. PBKDF2-HMAC-SHA1(password, salt, iterations, seed-size)
//  2. random-to-key(seed) - identity function for AES
//  3. DK(key, "kerberos") - derive using constant "kerberos"
//
// This final DK step is critical and often missed!
func AES256Key(password, salt string) []byte {
	// Step 1: PBKDF2 to get seed
	seed := pbkdf2.Key([]byte(password), []byte(salt), PBKDF2Iterations, AES256KeySize, sha1.New)

	// Step 2: random-to-key is identity for AES
	tkey := seed

	// Step 3: DK derivation with constant "kerberos"
	return dk(tkey, []byte("kerberos"), AES256KeySize)
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
//   - The key is derived using checksum key derivation (0x99)
//   - Key usage 17 = KERB_NON_KERB_CKSUM_SALT
//
// The checksum provides integrity AND authenticity since only
// the KDC or service knowing the key can produce a valid signature.
func HMACSHA1AES256(key, data []byte) ([]byte, error) {
	// Derive the checksum key (Ki) using key usage 17 + checksum derivation
	checksumKey := deriveAESKey(key, 17, "chk", AES256KeySize)

	h := hmac.New(sha1.New, checksumKey)
	h.Write(data)
	sig := h.Sum(nil)

	// Truncate to 12 bytes (96 bits) for HMAC-SHA1-96
	return sig[:12], nil
}

// HMACSHA1AES128 computes the HMAC-SHA1-96 checksum for AES128.
func HMACSHA1AES128(key, data []byte) ([]byte, error) {
	// Use "chk" (0x99) derivation with key usage 17 for PAC checksums
	checksumKey := deriveAESKey(key, 17, "chk", AES128KeySize)

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

// TestCTSDecrypt is an exported wrapper for testing aesCBCCTSDecrypt.
func TestCTSDecrypt(key, ciphertext []byte) ([]byte, error) {
	return aesCBCCTSDecrypt(key, ciphertext)
}

// TestCTSEncrypt is an exported wrapper for testing aesCBCCTSEncrypt.
func TestCTSEncrypt(key, plaintext []byte) ([]byte, error) {
	return aesCBCCTSEncrypt(key, plaintext)
}
