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

	// KERB_RETRIEVE_TKT_RESPONSE:
	//   Ticket: KERB_EXTERNAL_TICKET
	//     ServiceName, TargetName, etc.
	//     EncodedTicket: offset + length

	// Extract encoded ticket and parse as Kirbi
	// Placeholder - actual parsing needed
	return nil, fmt.Errorf("ticket parsing not implemented")
}

func encodeUTF16(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}
