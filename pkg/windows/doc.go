// Package windows provides Windows-specific Kerberos functionality.
//
// # Overview
//
// This package implements Windows API integrations:
//   - Pass-the-Ticket (PTT): Inject tickets into memory
//   - Ticket Dump: Extract tickets from LSASS
//   - Ticket Triage: List cached tickets
//   - TGTDeleg: Extract usable TGT without touching LSASS
//
// # Build Constraints
//
// This package only compiles on Windows (uses syscalls).
// Use build tags for cross-platform projects:
//
//	go build -tags "!windows" ./... // Exclude Windows code
//
// # Security Considerations
//
// Most operations require elevated privileges:
//   - PTT: Needs SeImpersonatePrivilege for other sessions
//   - Dump: Needs SeDebugPrivilege for LSASS access
//   - Triage: Can view own session without elevation
//   - TGTDeleg: Works with current user privileges!
//
// TGTDeleg is unique - it extracts a usable TGT without admin rights.
package windows
