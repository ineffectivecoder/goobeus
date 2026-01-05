package ticket

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

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
	Cred           *asn1krb5.KRBCred
	CredInfo       *asn1krb5.EncKRBCredPart // Decrypted credential info
	RawBytes       []byte                   // Raw KRB-CRED bytes (used when parsing fails but bytes are valid)
	DecryptKey     []byte                   // Session key for decrypting enc-part
	DecryptKeyType int                      // Session key encryption type
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
	originalData := data

	// Try to detect if it's base64 encoded
	if isBase64(data) {
		// Trim whitespace/newlines from base64 text files
		text := strings.TrimSpace(string(data))
		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
		data = decoded
		originalData = data
	}

	// First, verify this is APPLICATION 22 (KRB-CRED) - starts with 0x76
	if len(data) < 10 || data[0] != 0x76 {
		return nil, fmt.Errorf("not a valid KRB-CRED (expected APPLICATION 22)")
	}

	// Try Go's standard ASN.1 parsing first
	var cred asn1krb5.KRBCred
	rest, err := asn1.UnmarshalWithParams(data, &cred, "application,tag:22")
	if err == nil {
		if len(rest) > 0 {
			// Not an error, just extra data
		}

		kirbi := &Kirbi{Cred: &cred, RawBytes: originalData}

		// Parse the tickets from raw APPLICATION 1 wrapped bytes
		if err := cred.ParseTickets(); err != nil {
			// Non-fatal - continue without parsed tickets
		}

		// Try to extract credential info from enc-part
		// Usually encrypted with NULL key (etype 0)
		if cred.EncPart.EType == 0 || len(cred.EncPart.Cipher) > 0 {
			kirbi.CredInfo = parseCredInfo(cred.EncPart.Cipher)
		}

		return kirbi, nil
	}

	// Standard parsing failed (likely due to GeneralString 0x1b in tickets)
	// Parse manually to extract what we can

	// Parse APPLICATION 22 wrapper length
	_, lenBytes := parseKirbiLength(data[1:])
	seqStart := 1 + lenBytes

	// Skip to inner SEQUENCE (0x30)
	if seqStart >= len(data) || data[seqStart] != 0x30 {
		// Fallback to RawBytes-based kirbi
		return &Kirbi{RawBytes: originalData}, nil
	}

	// We have valid KRB-CRED structure - extract tickets and cred info manually
	kirbi := &Kirbi{RawBytes: originalData}

	// Extract the ticket bytes from the KRB-CRED and build Cred
	krbCred := manualParseKRBCred(data)
	if krbCred != nil {
		kirbi.Cred = krbCred
	}

	// Try to extract EncKRBCredPart from the enc-part for session key
	kirbi.CredInfo = parseCredInfoFromRaw(data)

	return kirbi, nil
}

// parseKirbiLength parses ASN.1 length encoding
func parseKirbiLength(data []byte) (int, int) {
	if len(data) == 0 {
		return -1, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || len(data) < 1+numBytes {
		return -1, 0
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes
}

// parseCredInfoFromRaw extracts EncKRBCredPart from raw KRB-CRED bytes.
// Must navigate past the tickets to find the KRB-CRED's enc-part, not ticket enc-parts.
func parseCredInfoFromRaw(data []byte) *asn1krb5.EncKRBCredPart {
	if len(data) < 20 || data[0] != 0x76 { // APPLICATION 22
		return nil
	}

	// Skip APPLICATION 22 header
	pos := 2
	if data[1] == 0x82 {
		pos = 4
	} else if data[1] == 0x81 {
		pos = 3
	}

	// Skip SEQUENCE header
	if data[pos] == 0x30 {
		if data[pos+1] == 0x82 {
			pos += 4
		} else if data[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Navigate KRB-CRED fields: [0] pvno, [1] msg-type, [2] tickets, [3] enc-part
	// We want [3] at THIS level, not nested in tickets
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			fieldLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		if tag == 3 { // enc-part of KRB-CRED
			encPartData := data[contentPos : contentPos+fieldLen]
			// Parse EncryptedData: SEQUENCE { [0] etype, [1?] kvno, [2] cipher }
			if len(encPartData) < 5 || encPartData[0] != 0x30 {
				return nil
			}

			// Find [2] cipher
			encPos := 2
			if encPartData[1] >= 0x80 {
				encPos = 2 + (int(encPartData[1]) - 0x80) + 1
			}

			for encPos < len(encPartData)-5 {
				if encPartData[encPos] == 0xa2 { // [2] cipher
					cipherLen := 0
					cipherStart := encPos + 2
					if encPartData[encPos+1] == 0x82 {
						cipherLen = (int(encPartData[encPos+2]) << 8) | int(encPartData[encPos+3])
						cipherStart = encPos + 4
					} else if encPartData[encPos+1] == 0x81 {
						cipherLen = int(encPartData[encPos+2])
						cipherStart = encPos + 3
					} else if encPartData[encPos+1] < 0x80 {
						cipherLen = int(encPartData[encPos+1])
					}

					if cipherStart+cipherLen > len(encPartData) {
						return nil
					}
					cipherWrapper := encPartData[cipherStart : cipherStart+cipherLen]

					// Unwrap OCTET STRING (0x04)
					if len(cipherWrapper) > 2 && cipherWrapper[0] == 0x04 {
						octetLen, octetLenBytes := parseKirbiLength(cipherWrapper[1:])
						if octetLen > 0 && 1+octetLenBytes+octetLen <= len(cipherWrapper) {
							cipherBytes := cipherWrapper[1+octetLenBytes : 1+octetLenBytes+octetLen]
							return parseCredInfo(cipherBytes)
						}
					}
				}
				encPos++
			}
			return nil
		}

		pos = contentPos + fieldLen
	}
	return nil
}

// manualParseKRBCred extracts KRBCred fields manually from raw bytes.
// This is needed when Go's asn1 fails due to GeneralString (0x1b) in tickets.
func manualParseKRBCred(data []byte) *asn1krb5.KRBCred {
	if len(data) < 20 || data[0] != 0x76 { // APPLICATION 22
		return nil
	}

	// Skip APPLICATION 22 header
	pos := 2
	if data[1] == 0x82 {
		pos = 4
	} else if data[1] == 0x81 {
		pos = 3
	}

	// Skip SEQUENCE header
	if data[pos] == 0x30 {
		if data[pos+1] == 0x82 {
			pos += 4
		} else if data[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	cred := &asn1krb5.KRBCred{
		PVNO:    5,
		MsgType: 22,
	}

	// Parse fields: [0] pvno, [1] msg-type, [2] tickets (SEQUENCE OF), [3] enc-part
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			fieldLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		if tag == 2 { // tickets - SEQUENCE OF Ticket
			ticketsData := data[contentPos : contentPos+fieldLen]
			// Parse SEQUENCE wrapper
			if ticketsData[0] == 0x30 {
				seqLen := 0
				seqPos := 2
				if ticketsData[1] == 0x82 {
					seqLen = (int(ticketsData[2]) << 8) | int(ticketsData[3])
					seqPos = 4
				} else if ticketsData[1] == 0x81 {
					seqLen = int(ticketsData[2])
					seqPos = 3
				} else {
					seqLen = int(ticketsData[1])
				}

				// Each ticket is APPLICATION 1 (0x61)
				ticketStart := seqPos
				for ticketStart < seqPos+seqLen {
					if ticketsData[ticketStart] == 0x61 {
						ticketLen := 0
						ticketHeaderLen := 2
						if ticketsData[ticketStart+1] == 0x82 {
							ticketLen = (int(ticketsData[ticketStart+2]) << 8) | int(ticketsData[ticketStart+3])
							ticketHeaderLen = 4
						} else if ticketsData[ticketStart+1] == 0x81 {
							ticketLen = int(ticketsData[ticketStart+2])
							ticketHeaderLen = 3
						} else {
							ticketLen = int(ticketsData[ticketStart+1])
						}

						ticketBytes := ticketsData[ticketStart : ticketStart+ticketHeaderLen+ticketLen]
						ticket := asn1krb5.Ticket{
							TktVno:   5,
							RawBytes: ticketBytes,
						}
						// Extract realm and sname from ticket for basic info
						extractTicketBasicInfo(ticketBytes, &ticket)
						cred.Tickets = append(cred.Tickets, ticket)

						ticketStart += ticketHeaderLen + ticketLen
					} else {
						break
					}
				}
			}
		}

		pos = contentPos + fieldLen
	}

	if len(cred.Tickets) == 0 {
		return nil
	}

	return cred
}

// extractTicketBasicInfo extracts realm and sname from ticket bytes.
func extractTicketBasicInfo(data []byte, ticket *asn1krb5.Ticket) {
	if len(data) < 10 || data[0] != 0x61 { // APPLICATION 1
		return
	}

	// Skip APPLICATION 1 header
	pos := 2
	if data[1] == 0x82 {
		pos = 4
	} else if data[1] == 0x81 {
		pos = 3
	}

	// Skip SEQUENCE header
	if data[pos] == 0x30 {
		if data[pos+1] == 0x82 {
			pos += 4
		} else if data[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Parse fields: [0] tkt-vno, [1] realm, [2] sname, [3] enc-part
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			fieldLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		fieldData := data[contentPos : contentPos+fieldLen]

		if tag == 1 { // realm
			// GeneralString (0x1b) or PrintableString (0x13)
			if len(fieldData) > 2 && (fieldData[0] == 0x1b || fieldData[0] == 0x13) {
				strLen := int(fieldData[1])
				if 2+strLen <= len(fieldData) {
					ticket.Realm = string(fieldData[2 : 2+strLen])
				}
			}
		} else if tag == 2 { // sname - PrincipalName
			// PrincipalName ::= SEQUENCE { [0] name-type, [1] name-string SEQUENCE OF GeneralString }
			// Parse the SEQUENCE
			if len(fieldData) > 5 && fieldData[0] == 0x30 {
				seqPos := 2
				if fieldData[1] >= 0x80 {
					seqPos = 2 + int(fieldData[1]&0x7f)
				}

				// Find [1] name-string
				for seqPos < len(fieldData)-3 {
					if fieldData[seqPos] == 0xa0 { // [0] name-type
						// Skip it
						innerLen := int(fieldData[seqPos+1])
						if fieldData[seqPos+1] >= 0x80 {
							innerLen = int(fieldData[seqPos+2])
							seqPos += 3 + innerLen
						} else {
							seqPos += 2 + innerLen
						}
					} else if fieldData[seqPos] == 0xa1 { // [1] name-string
						// This contains SEQUENCE OF GeneralString
						innerStart := seqPos + 2
						if fieldData[seqPos+1] >= 0x80 {
							innerStart = seqPos + 3
						}
						if innerStart < len(fieldData) && fieldData[innerStart] == 0x30 {
							// Skip inner SEQUENCE header
							stringsStart := innerStart + 2
							if fieldData[innerStart+1] >= 0x80 {
								stringsStart = innerStart + 2 + int(fieldData[innerStart+1]&0x7f)
							}

							// Extract GeneralStrings
							var nameStrings []string
							for stringsStart < len(fieldData)-2 {
								if fieldData[stringsStart] == 0x1b || fieldData[stringsStart] == 0x13 { // GeneralString or PrintableString
									strLen := int(fieldData[stringsStart+1])
									if stringsStart+2+strLen <= len(fieldData) {
										nameStrings = append(nameStrings, string(fieldData[stringsStart+2:stringsStart+2+strLen]))
										stringsStart += 2 + strLen
									} else {
										break
									}
								} else {
									break
								}
							}
							if len(nameStrings) > 0 {
								ticket.SName = asn1krb5.PrincipalName{
									NameType:   asn1krb5.NTSrvInst,
									NameString: nameStrings,
								}
							}
						}
						break
					} else {
						seqPos++
					}
				}
			}
		} else if tag == 3 { // enc-part
			// Extract etype from EncryptedData
			if len(fieldData) > 10 && fieldData[0] == 0x30 {
				// Skip SEQUENCE header, find [0] etype
				encPos := 2
				if fieldData[1] == 0x82 {
					encPos = 4 // 0x30 0x82 LL LL
				} else if fieldData[1] == 0x81 {
					encPos = 3 // 0x30 0x81 LL
				}
				if encPos < len(fieldData) && fieldData[encPos] == 0xa0 {
					etypeStart := encPos + 4
					if etypeStart < len(fieldData) && fieldData[etypeStart-2] == 0x02 {
						ticket.EncPart.EType = int32(fieldData[etypeStart])
					}
				}
			}
		}

		pos = contentPos + fieldLen
	}
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
// Uses custom marshaling to properly handle APPLICATION tags on Ticket.
func (k *Kirbi) Marshal() ([]byte, error) {
	// If we have raw bytes (from unparseable KRB-CRED), return them directly
	if len(k.RawBytes) > 0 {
		return k.RawBytes, nil
	}

	if k.Cred == nil {
		return nil, fmt.Errorf("no KRB-CRED to marshal")
	}

	// Marshal each ticket with APPLICATION 1 wrapper
	var ticketBytes [][]byte
	for _, tkt := range k.Cred.Tickets {
		data, err := tkt.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshaling ticket: %w", err)
		}
		ticketBytes = append(ticketBytes, data)
	}

	// Build the tickets SEQUENCE manually
	var ticketsSeq []byte
	for _, tb := range ticketBytes {
		ticketsSeq = append(ticketsSeq, tb...)
	}

	// Wrap in SEQUENCE tag
	ticketsWrapper := wrapSequence(ticketsSeq)

	// Marshal CredInfo into EncPart if present
	// EncKRBCredPart uses APPLICATION 29 tag
	// We use custom marshaling to match Rubeus exactly (Go's asn1 doesn't do GeneralString properly)
	encPart := k.Cred.EncPart
	if k.CredInfo != nil && len(encPart.Cipher) == 0 {
		credInfoData := MarshalEncKRBCredPart(k.CredInfo)
		encPart.Cipher = credInfoData
		encPart.EType = 0 // NULL encryption
	}

	// Marshal enc-part
	encPartData, err := asn1.Marshal(encPart)
	if err != nil {
		return nil, fmt.Errorf("marshaling enc-part: %w", err)
	}

	// Build inner KRB-CRED SEQUENCE
	// [0] pvno INTEGER, [1] msg-type INTEGER, [2] tickets SEQUENCE OF Ticket, [3] enc-part EncryptedData
	pvnoData, _ := asn1.Marshal(k.Cred.PVNO)
	msgTypeData, _ := asn1.Marshal(k.Cred.MsgType)

	inner := []byte{}
	inner = append(inner, wrapContextTag(0, pvnoData)...)
	inner = append(inner, wrapContextTag(1, msgTypeData)...)
	inner = append(inner, wrapContextTag(2, ticketsWrapper)...)
	inner = append(inner, wrapContextTag(3, encPartData)...)

	// Wrap in SEQUENCE
	seq := wrapSequence(inner)

	// Wrap in APPLICATION 22 (KRB-CRED)
	return wrapApplication(22, seq), nil
}

func wrapSequence(data []byte) []byte {
	return wrapTLV(0x30, data)
}

func wrapContextTag(tag int, data []byte) []byte {
	return wrapTLV(byte(0xa0+tag), data)
}

func wrapApplication(tag int, data []byte) []byte {
	return wrapTLV(byte(0x60+tag), data)
}

func wrapTLV(tag byte, data []byte) []byte {
	length := len(data)
	var result []byte
	result = append(result, tag)
	if length < 128 {
		result = append(result, byte(length))
	} else if length < 256 {
		result = append(result, 0x81, byte(length))
	} else {
		result = append(result, 0x82, byte(length>>8), byte(length&0xff))
	}
	return append(result, data...)
}

// MarshalEncKRBCredPart encodes EncKRBCredPart exactly like Rubeus does.
// This is critical for PTT to work - Go's asn1 package doesn't handle GeneralString properly.
func MarshalEncKRBCredPart(cred *asn1krb5.EncKRBCredPart) []byte {
	if cred == nil || len(cred.TicketInfo) == 0 {
		return nil
	}

	// Marshal KrbCredInfo
	infoBytes := marshalKRBCredInfo(&cred.TicketInfo[0])

	// ticket-info [0] SEQUENCE OF KrbCredInfo
	// Structure: [0] -> SEQUENCE OF -> KrbCredInfo
	// The KrbCredInfo itself is already a SEQUENCE, so we just wrap it in SEQUENCE OF
	seqOf := wrapSequence(infoBytes)             // SEQUENCE OF containing KrbCredInfo
	ticketInfoTagged := wrapContextTag(0, seqOf) // [0] tag

	// EncKrbCredPart SEQUENCE
	totalSeq := wrapSequence(ticketInfoTagged)

	// [APPLICATION 29]
	return wrapApplication(29, totalSeq)
}

// marshalKRBCredInfo encodes a single KRBCredInfo exactly like Rubeus.
func marshalKRBCredInfo(info *asn1krb5.KRBCredInfo) []byte {
	var elements []byte

	// Helper for GeneralString (0x1b)
	buildGeneralString := func(s string) []byte {
		data := []byte(s)
		result := []byte{0x1b}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	// Helper to build INTEGER
	buildInt := func(n int) []byte {
		if n == 0 {
			return []byte{0x02, 0x01, 0x00}
		}
		if n > 0 && n < 128 {
			return []byte{0x02, 0x01, byte(n)}
		}
		if n >= 128 && n < 256 {
			return []byte{0x02, 0x02, 0x00, byte(n)}
		}
		// Handle larger values
		return []byte{0x02, 0x04, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}

	// Helper to build GeneralizedTime (yyyyMMddHHmmssZ format)
	buildGenTime := func(t time.Time) []byte {
		timeStr := t.UTC().Format("20060102150405Z")
		data := []byte(timeStr)
		result := []byte{0x18} // GeneralizedTime tag
		result = append(result, byte(len(data)))
		return append(result, data...)
	}

	// [0] key - EncryptionKey ::= SEQUENCE { [0] keytype INTEGER, [1] keyvalue OCTET STRING }
	keyTypeBytes := wrapContextTag(0, buildInt(int(info.Key.KeyType)))
	keyValueBytes := wrapContextTag(1, wrapOctetString(info.Key.KeyValue))
	keySeq := wrapSequence(append(keyTypeBytes, keyValueBytes...))
	elements = append(elements, wrapContextTag(0, keySeq)...)

	// [1] prealm (GeneralString) - optional
	if info.PRealm != "" {
		elements = append(elements, wrapContextTag(1, buildGeneralString(info.PRealm))...)
	}

	// [2] pname (PrincipalName) - optional
	if len(info.PName.NameString) > 0 && info.PName.NameString[0] != "" {
		pnameBytes := marshalPrincipalName(&info.PName, buildGeneralString)
		elements = append(elements, wrapContextTag(2, pnameBytes)...)
	}

	// [3] flags (BIT STRING) - always encode (Rubeus always does)
	// BIT STRING encoding: tag(1) + length(1) + unused_bits(1) + 4 bytes of flags = 7 bytes
	flagBytes := make([]byte, 7)
	flagBytes[0] = 0x03 // BIT STRING tag
	flagBytes[1] = 0x05 // length 5 (unused_bits byte + 4 flag bytes)
	flagBytes[2] = 0x00 // unused bits
	if len(info.Flags.Bytes) >= 4 {
		// Flags are stored big-endian in BitString
		copy(flagBytes[3:7], info.Flags.Bytes[:4])
	}
	elements = append(elements, wrapContextTag(3, flagBytes)...)

	// [4] authtime - optional
	if !info.AuthTime.IsZero() {
		elements = append(elements, wrapContextTag(4, buildGenTime(info.AuthTime))...)
	}

	// [5] starttime - optional
	if !info.StartTime.IsZero() {
		elements = append(elements, wrapContextTag(5, buildGenTime(info.StartTime))...)
	}

	// [6] endtime - optional
	if !info.EndTime.IsZero() {
		elements = append(elements, wrapContextTag(6, buildGenTime(info.EndTime))...)
	}

	// [7] renew-till - optional
	if !info.RenewTill.IsZero() {
		elements = append(elements, wrapContextTag(7, buildGenTime(info.RenewTill))...)
	}

	// [8] srealm (GeneralString) - optional
	if info.SRealm != "" {
		elements = append(elements, wrapContextTag(8, buildGeneralString(info.SRealm))...)
	}

	// [9] sname (PrincipalName) - optional
	if len(info.SName.NameString) > 0 && info.SName.NameString[0] != "" {
		snameBytes := marshalPrincipalName(&info.SName, buildGeneralString)
		elements = append(elements, wrapContextTag(9, snameBytes)...)
	}

	// [10] caddr - not used

	return wrapSequence(elements)
}

// marshalPrincipalName encodes a PrincipalName using GeneralString.
func marshalPrincipalName(p *asn1krb5.PrincipalName, buildGeneralString func(string) []byte) []byte {
	// [0] name-type INTEGER
	nameTypeInt := []byte{0x02, 0x01, byte(p.NameType)}
	nameType := wrapContextTag(0, nameTypeInt)

	// [1] name-string SEQUENCE OF GeneralString
	var nameStrings []byte
	for _, s := range p.NameString {
		nameStrings = append(nameStrings, buildGeneralString(s)...)
	}
	nameString := wrapContextTag(1, wrapSequence(nameStrings))

	return wrapSequence(append(nameType, nameString...))
}

// wrapOctetString wraps data in an OCTET STRING
func wrapOctetString(data []byte) []byte {
	return wrapTLV(0x04, data)
}

// buildLen creates ASN.1 length encoding
func buildLen(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	} else if l < 256 {
		return []byte{0x81, byte(l)}
	}
	return []byte{0x82, byte(l >> 8), byte(l)}
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

	// Apply GeneralString (0x1b) to PrintableString (0x13) workaround
	// because Go's asn1 package doesn't handle GeneralString
	dataFixed := make([]byte, len(data))
	copy(dataFixed, data)
	for i := range dataFixed {
		if dataFixed[i] == 0x1b {
			dataFixed[i] = 0x13
		}
	}

	var credPart asn1krb5.EncKRBCredPart
	_, err := asn1.UnmarshalWithParams(dataFixed, &credPart, "application,tag:29")
	if err != nil {
		// Try without application tag
		_, err = asn1.Unmarshal(dataFixed, &credPart)
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

	first := data[0]

	// Check if this looks like valid DER-encoded ASN.1
	// Binary DER data starts with specific tag bytes followed by valid length encoding
	// 0x30 = SEQUENCE, 0x60-0x7F = APPLICATION tags, 0xA0-0xBF = CONTEXT tags
	if first == 0x30 || (first >= 0xA0 && first <= 0xBF) {
		// These are definitely binary ASN.1 tags that don't overlap with printable ASCII
		return false
	}

	// For 0x60-0x7F range (APPLICATION tags), we need to be careful:
	// 0x76 = APPLICATION 22 (KRB-CRED) - this is valid DER
	// But 0x61-0x7A are also lowercase 'a'-'z' which are base64!
	// Check if it looks like valid DER by checking the length encoding
	if first >= 0x60 && first <= 0x7F && len(data) > 2 {
		// Valid DER has a length byte after the tag
		// If second byte is 0x82, it's a 2-byte length (very common for KRB-CRED)
		// If second byte is 0x81, it's a 1-byte length
		// If second byte < 0x80, it's a short length
		lenByte := data[1]
		if lenByte == 0x82 && len(data) > 4 {
			// Long form 2-byte length - calculate and verify
			declaredLen := int(data[2])<<8 | int(data[3])
			// If declared length roughly matches data length, this is likely DER
			if declaredLen > 100 && declaredLen <= len(data) {
				return false // This is binary DER
			}
		} else if lenByte == 0x81 && len(data) > 3 {
			// Long form 1-byte length
			declaredLen := int(data[2])
			if declaredLen > 0 && declaredLen+3 <= len(data) {
				return false // This is binary DER
			}
		}
		// If length encoding doesn't look valid, this is probably text
	}

	// Base64 data typically contains only these characters
	// Check first byte and also verify a few more chars look like base64
	if (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || (first >= '0' && first <= '9') || first == '+' || first == '/' {
		// Verify more characters to be sure
		for i := 1; i < len(data) && i < 10; i++ {
			c := data[i]
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r') {
				return false // Invalid base64 character
			}
		}
		return true
	}

	return false
}
