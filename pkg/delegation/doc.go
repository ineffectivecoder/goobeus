// Package delegation provides Kerberos delegation attack utilities.
//
// # Overview
//
// Kerberos delegation allows services to impersonate users. This package
// helps discover and exploit delegation configurations:
//
//   - Unconstrained: Capture TGTs from connecting users
//   - Constrained: Impersonate users to allowed services
//   - RBCD: Abuse write access to computer objects
//
// # Attack Types
//
// Unconstrained Delegation:
//   - Service caches TGT of any connecting user
//   - Compromise service → steal TGTs → impersonate users anywhere
//   - Trigger with PrinterBug, PetitPotam, etc.
//
// Constrained Delegation:
//   - Service can impersonate users to specific SPNs only
//   - Use S4U2Self + S4U2Proxy to get tickets as any user
//   - msDS-AllowedToDelegateTo lists allowed targets
//
// RBCD (Resource-Based Constrained Delegation):
//   - Target specifies who can delegate TO it
//   - Write access to computer = add ourselves = compromise
//   - msDS-AllowedToActOnBehalfOfOtherIdentity attribute
package delegation
