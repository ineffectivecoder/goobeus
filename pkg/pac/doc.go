// Package pac provides PAC (Privilege Attribute Certificate) handling.
//
// # Overview
//
// The PAC is Microsoft's extension to Kerberos tickets containing:
//   - User SID and group memberships
//   - Logon information (name, domain, etc.)
//   - Privilege data
//   - Signatures for integrity
//
// # Why PAC Matters
//
// The PAC is what Windows uses for authorization. When you access a resource,
// Windows checks your SID and group SIDs in the PAC against the ACL.
//
// In Golden/Silver ticket attacks, we FORGE the PAC to add ourselves
// to any group (like Domain Admins) without actually having membership!
//
// # PAC Structure
//
// A PAC contains multiple buffers:
//   - LOGON_INFO: User info, SIDs, groups
//   - CLIENT_INFO: Client name and auth time
//   - SERVER_CHECKSUM: Signature with service key
//   - KDC_CHECKSUM: Signature with krbtgt key
//   - UPN_DNS_INFO: UPN and DNS domain
//
// The signatures prevent modification UNLESS you have the keys.
// With the krbtgt key (Golden) or service key (Silver), we can sign!
package pac
