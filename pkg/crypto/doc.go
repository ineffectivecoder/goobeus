// Package crypto provides Kerberos encryption and key derivation.
//
// # Overview
//
// Kerberos uses encryption types (etypes) to identify which cryptographic
// algorithm to use. This package implements the most common types:
//
//	Etype 23: RC4-HMAC-MD5   (most common, key = NTLM hash)
//	Etype 17: AES128-CTS-HMAC-SHA1-96
//	Etype 18: AES256-CTS-HMAC-SHA1-96
//
// # Why RC4 is Still Common
//
// Despite being cryptographically weak, RC4-HMAC remains prevalent because:
//
//  1. The key IS the NTLM hash - no key derivation needed
//  2. This enables pass-the-hash attacks with just the NTLM hash
//  3. Legacy Windows systems require RC4 for compatibility
//  4. Service accounts often configured before AES was default
//
// # Key Derivation
//
// For RC4:
//
//	key = MD4(UTF16-LE(password))  // This IS the NTLM hash
//
// For AES:
//
//	key = PBKDF2-HMAC-SHA1(password, salt, 4096, keysize)
//	salt = uppercase(REALM) + username
//
// # Security Note
//
// When attacking:
//   - Always prefer cracking RC4 tickets (1000x faster than AES)
//   - Request RC4 etype explicitly when Kerberoasting: --enctype rc4
//   - Many services still accept RC4 even when AES is available
package crypto
