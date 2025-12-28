//go:build windows
// +build windows

package windows

import (
	"fmt"
	"syscall"
	"unsafe"
)

// EDUCATIONAL: LUID Operations and NetOnly Process Creation
//
// LUID (Locally Unique Identifier) identifies logon sessions in Windows.
// Each logon gets a unique LUID, and tickets are cached per-session.
//
// Operations:
//   - Get current LUID
//   - List all logon sessions (elevated)
//   - Switch session context for ticket operations
//
// NetOnly Process:
//   - Creates process with network credentials only
//   - Local actions use current identity
//   - Network actions use specified credentials
//   - Great for using different domain creds

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procGetCurrentProcess       = kernel32.NewProc("GetCurrentProcess")
	procOpenProcessToken        = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation     = advapi32.NewProc("GetTokenInformation")
	procCreateProcessWithLogonW = advapi32.NewProc("CreateProcessWithLogonW")
)

// LUID represents a Windows Locally Unique Identifier.
type LUID struct {
	LowPart  uint32
	HighPart int32
}

// String returns the LUID as a hex string.
func (l LUID) String() string {
	return fmt.Sprintf("0x%x:0x%x", l.HighPart, l.LowPart)
}

// GetCurrentLUID gets the LUID of the current logon session.
func GetCurrentLUID() (*LUID, error) {
	// Open current process token
	var token syscall.Handle
	process, _, _ := procGetCurrentProcess.Call()

	ret, _, err := procOpenProcessToken.Call(
		process,
		0x0008, // TOKEN_QUERY
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer syscall.CloseHandle(token)

	// Get token statistics for LUID
	type tokenStatistics struct {
		TokenId            LUID
		AuthenticationId   LUID
		ExpirationTime     int64
		TokenType          uint32
		ImpersonationLevel uint32
		DynamicCharged     uint32
		DynamicAvailable   uint32
		GroupCount         uint32
		PrivilegeCount     uint32
		ModifiedId         LUID
	}

	var stats tokenStatistics
	var returnLength uint32

	ret, _, err = procGetTokenInformation.Call(
		uintptr(token),
		10, // TokenStatistics
		uintptr(unsafe.Pointer(&stats)),
		uintptr(unsafe.Sizeof(stats)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("GetTokenInformation failed: %v", err)
	}

	return &stats.AuthenticationId, nil
}

// LogonSession represents a Windows logon session.
type LogonSession struct {
	LUID        LUID
	Username    string
	Domain      string
	LogonType   uint32
	AuthPackage string
	LogonTime   int64
}

// EnumerateLogonSessions lists all logon sessions (requires elevation).
func EnumerateLogonSessions() ([]LogonSession, error) {
	// Would call LsaEnumerateLogonSessions + LsaGetLogonSessionData
	// Requires SeDebugPrivilege or running elevated
	return nil, fmt.Errorf("not implemented - requires LsaEnumerateLogonSessions")
}

// NetOnlyProcessRequest configures a NetOnly process creation.
type NetOnlyProcessRequest struct {
	// Credentials for network operations
	Username string
	Domain   string
	Password string

	// Process to launch
	CommandLine string
	WorkingDir  string
}

// CreateNetOnlyProcess creates a process with network-only credentials.
//
// EDUCATIONAL: NetOnly Logon
//
// NetOnly (LOGON32_LOGON_NEW_CREDENTIALS) is powerful for:
//   - Testing access with different credentials
//   - Using admin creds for network without local elevation
//   - Avoiding pass-the-hash complications
//
// The process runs as YOU locally, but uses the specified creds
// for all network authentication (SMB, Kerberos, etc.).
func CreateNetOnlyProcess(req *NetOnlyProcessRequest) error {
	if req.Username == "" || req.Password == "" {
		return fmt.Errorf("username and password are required")
	}
	if req.CommandLine == "" {
		req.CommandLine = "cmd.exe"
	}

	// Convert strings to UTF16
	username, _ := syscall.UTF16PtrFromString(req.Username)
	domain, _ := syscall.UTF16PtrFromString(req.Domain)
	password, _ := syscall.UTF16PtrFromString(req.Password)
	commandLine, _ := syscall.UTF16PtrFromString(req.CommandLine)

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation

	// LOGON_NETCREDENTIALS_ONLY = 2
	ret, _, err := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		2, // LOGON_NETCREDENTIALS_ONLY
		0, // lpApplicationName (NULL)
		uintptr(unsafe.Pointer(commandLine)),
		0, // dwCreationFlags
		0, // lpEnvironment
		0, // lpCurrentDirectory
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return fmt.Errorf("CreateProcessWithLogonW failed: %v", err)
	}

	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)

	return nil
}
