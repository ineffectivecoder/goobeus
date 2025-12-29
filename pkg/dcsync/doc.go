// Package dcsync implements DCSync attack using MS-DRSR protocol.
//
// EDUCATIONAL: DCSync Attack
//
// DCSync abuses the Directory Replication Service Remote Protocol (MS-DRSR)
// to request password hashes from a Domain Controller. The attacker
// impersonates a DC requesting replication data.
//
// How it works:
//  1. Authenticate to DC with creds that have replication rights
//  2. Call DsBind to get a replication handle
//  3. Call DsGetNCChanges requesting user's password attributes
//  4. Decrypt the replicated secrets using the DC's session key
//
// Required privileges:
//   - DS-Replication-Get-Changes
//   - DS-Replication-Get-Changes-All
//   - Replicating Directory Changes In Filtered Set (for RODC filtered attrs)
//
// Default holders:
//   - Domain Admins
//   - Enterprise Admins
//   - Administrators (on DC)
//   - Domain Controllers
//
// This is the FIRST pure-Go Windows-native DCSync implementation!
package dcsync
