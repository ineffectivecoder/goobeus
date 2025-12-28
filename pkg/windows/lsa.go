//go:build windows
// +build windows

package windows

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Windows Kerberos APIs
//
// Windows stores Kerberos tickets in the LSA (Local Security Authority).
// We interact with LSA using these APIs:
//
// LsaConnectUntrusted - Connect to LSA without admin
// LsaCallAuthenticationPackage - Call Kerberos SSP
// LsaLookupAuthenticationPackage - Get Kerberos package ID
// LsaDeregisterLogonProcess - Cleanup
//
// For elevated access (dump all tickets):
// LsaRegisterLogonProcess - Connect with admin rights
// NtOpenProcess - Open LSASS process
// NtReadVirtualMemory - Read ticket data

var (
	secur32  = syscall.NewLazyDLL("secur32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procLsaConnectUntrusted            = secur32.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPackage   = secur32.NewProc("LsaCallAuthenticationPackage")
	procLsaDeregisterLogonProcess      = secur32.NewProc("LsaDeregisterLogonProcess")
	procLsaFreeReturnBuffer            = secur32.NewProc("LsaFreeReturnBuffer")
)

// LSA handle type
type lsaHandle uintptr

// LSA_STRING for package names
type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

// Connect to LSA (untrusted mode - no admin required)
func lsaConnect() (lsaHandle, error) {
	var handle lsaHandle
	ret, _, _ := procLsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("LsaConnectUntrusted failed: 0x%x", ret)
	}
	return handle, nil
}

// Get Kerberos package ID
func lsaLookupKerberosPackage(handle lsaHandle) (uint32, error) {
	packageName := []byte("Kerberos\x00")
	lsaStr := lsaString{
		Length:        8,
		MaximumLength: 9,
		Buffer:        &packageName[0],
	}

	var packageID uint32
	ret, _, _ := procLsaLookupAuthenticationPackage.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&lsaStr)),
		uintptr(unsafe.Pointer(&packageID)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("LsaLookupAuthenticationPackage failed: 0x%x", ret)
	}
	return packageID, nil
}

// Disconnect from LSA
func lsaDisconnect(handle lsaHandle) {
	procLsaDeregisterLogonProcess.Call(uintptr(handle))
}

// TicketCache represents cached Kerberos tickets.
type TicketCache struct {
	Tickets []CachedTicket
}

// CachedTicket represents a single cached ticket.
type CachedTicket struct {
	ServerName     string
	RealmName      string
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
	Ticket         *ticket.Kirbi
}
