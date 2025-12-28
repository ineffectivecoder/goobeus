package ticket

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
)

// EDUCATIONAL: The .kirbi Format
//
// .kirbi files are the Windows-native Kerberos credential storage format.
// They contain a KRB-CRED ASN.1 message (RFC 4120, section 5.8).
//
// Structure:
//   KRB-CRED ::= [APPLICATION 22] SEQUENCE {
//       pvno            [0] INTEGER (5),
//       msg-type        [1] INTEGER (22),
//       tickets         [2] SEQUENCE OF Ticket,
//       enc-part        [3] EncryptedData
//   }
//
// The enc-part is typically encrypted with a NULL key (etype 0),
// meaning the session key is essentially in plaintext. This is what
// makes .kirbi files portable between machines!
//
// Tools that use .kirbi: Mimikatz, Rubeus, Kekeo

// Kirbi wraps a KRB-CRED for convenient .kirbi operations.
type Kirbi struct {
	Cred     *asn1krb5.KRBCred
	CredInfo *asn1krb5.EncKRBCredPart // Decrypted credential info
}

// LoadKirbi reads a .kirbi file from disk.
//
// EDUCATIONAL: Reading .kirbi Files
//
// .kirbi files are raw DER-encoded ASN.1. They have an APPLICATION 22
// tag wrapping the KRB-CRED structure. The file can be:
//   - Binary DER (most common from Mimikatz/Rubeus dump)
//   - Base64 encoded (from Rubeus base64 output)
func LoadKirbi(path string) (*Kirbi, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read kirbi file: %w", err)
	}

	return ParseKirbi(data)
}

// ParseKirbi parses raw .kirbi bytes (handles both binary and base64).
func ParseKirbi(data []byte) (*Kirbi, error) {
	// Try to detect if it's base64 encoded
	if isBase64(data) {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
		data = decoded
	}

	// Parse the ASN.1 KRB-CRED structure
	// KRB-CRED has APPLICATION tag 22
	var cred asn1krb5.KRBCred
	rest, err := asn1.UnmarshalWithParams(data, &cred, "application,tag:22")
	if err != nil {
		return nil, fmt.Errorf("failed to parse kirbi ASN.1: %w", err)
	}
	if len(rest) > 0 {
		// Not an error, just extra data
	}

	kirbi := &Kirbi{Cred: &cred}

	// Try to extract credential info from enc-part
	// Usually encrypted with NULL key (etype 0)
	if cred.EncPart.EType == 0 || len(cred.EncPart.Cipher) > 0 {
		kirbi.CredInfo = parseCredInfo(cred.EncPart.Cipher)
	}

	return kirbi, nil
}

// SaveKirbi writes a .kirbi file to disk.
func SaveKirbi(kirbi *Kirbi, path string) error {
	data, err := kirbi.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Marshal encodes the Kirbi to DER bytes.
func (k *Kirbi) Marshal() ([]byte, error) {
	return asn1.MarshalWithParams(k.Cred, "application,tag:22")
}

// ToBytes is an alias for Marshal (for PTT compatibility).
func (k *Kirbi) ToBytes() ([]byte, error) {
	return k.Marshal()
}

// ToBase64 encodes the Kirbi to a base64 string.
//
// EDUCATIONAL: Base64 Tickets
//
// Base64-encoded tickets are used for:
//   - Command-line passing (Rubeus ptt /ticket:BASE64)
//   - Embedding in scripts
//   - Copy-paste between systems
func (k *Kirbi) ToBase64() (string, error) {
	data, err := k.Marshal()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// FromBase64 decodes a base64-encoded .kirbi.
func FromBase64(b64 string) (*Kirbi, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	return ParseKirbi(data)
}

// Ticket returns the first ticket from the KRB-CRED.
// Most .kirbi files contain exactly one ticket.
func (k *Kirbi) Ticket() *asn1krb5.Ticket {
	if k.Cred == nil || len(k.Cred.Tickets) == 0 {
		return nil
	}
	return &k.Cred.Tickets[0]
}

// SessionKey returns the session key for the ticket (if available).
func (k *Kirbi) SessionKey() *asn1krb5.EncryptionKey {
	if k.CredInfo == nil || len(k.CredInfo.TicketInfo) == 0 {
		return nil
	}
	return &k.CredInfo.TicketInfo[0].Key
}

// parseCredInfo attempts to parse EncKRBCredPart from cipher bytes.
// For NULL-encrypted (etype 0), the cipher IS the DER-encoded EncKRBCredPart.
func parseCredInfo(data []byte) *asn1krb5.EncKRBCredPart {
	if len(data) == 0 {
		return nil
	}

	var credPart asn1krb5.EncKRBCredPart
	_, err := asn1.UnmarshalWithParams(data, &credPart, "application,tag:29")
	if err != nil {
		// Try without application tag
		_, err = asn1.Unmarshal(data, &credPart)
		if err != nil {
			return nil
		}
	}
	return &credPart
}

// isBase64 checks if data appears to be base64 encoded.
func isBase64(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Base64 data typically starts with letters or numbers
	// DER data starts with 0x30 (SEQUENCE) or 0x76 (APPLICATION 22)
	first := data[0]
	return first >= 'A' && first <= 'z' || first >= '0' && first <= '9'
}
