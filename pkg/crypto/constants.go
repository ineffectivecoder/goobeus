package crypto

// EDUCATIONAL: Kerberos Encryption Type Constants
//
// These constants define the encryption algorithms used in Kerberos.
// The choice of etype affects both security and attack feasibility.

// Encryption type (etype) constants
const (
	// EtypeRC4 is RC4-HMAC-MD5 (etype 23), also known as arcfour-hmac.
	// This is the most common etype because the key IS the NTLM hash,
	// enabling pass-the-hash attacks.
	EtypeRC4 = EtypeRC4HMAC // Alias for consistency

	// EtypeAES128 and EtypeAES256 are already defined in aes.go
	// - EtypeAES128 = 17 (aes128-cts-hmac-sha1-96)
	// - EtypeAES256 = 18 (aes256-cts-hmac-sha1-96)
)

// EDUCATIONAL: Key Usage Numbers
//
// Key usage numbers ensure different keys are used for different purposes,
// preventing cut-and-paste attacks. Each message type has a specific usage.
//
// RFC 4120 defines the key usage values for various Kerberos messages.

// Key usage constants
const (
	// Pre-authentication
	KeyUsagePAEncTimestamp = 1 // PA-ENC-TIMESTAMP encryption

	// AS-REP
	KeyUsageASRepTGSRepEncPart = 3 // AS-REP or TGS-REP encrypted part

	// Ticket
	KeyUsageTicket = 2 // Ticket encrypted part

	// TGS-REQ
	KeyUsageTGSReqAuthSubkey   = 4  // TGS-REQ auth. subkey
	KeyUsageTGSReqAuthChecksum = 6  // TGS-REQ auth. checksum
	KeyUsageTGSReqPAData       = 7  // TGS-REQ PA-TGS-REQ padata
	KeyUsageAPReqAuthChecksum  = 10 // AP-REQ authenticator checksum
	KeyUsageAPReqAuthSubkey    = 11 // AP-REQ authenticator subkey

	// Aliases for clarity
	KeyUsageASRepEncPart = KeyUsageASRepTGSRepEncPart // 3

	// TGS-REP encrypted with TGT session key uses key usage 8
	// (NOT 3 which is for AS-REP encrypted with client's long-term key)
	KeyUsageTGSRepSessionKey = 8
)
