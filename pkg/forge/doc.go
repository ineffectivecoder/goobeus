// Package forge provides Kerberos ticket forgery.
//
// # Overview
//
// This package implements ticket forgery attacks:
//   - Golden Ticket: Forge TGT with krbtgt hash (domain persistence)
//   - Silver Ticket: Forge service ticket with service hash
//   - Diamond Ticket: Request real TGT, modify PAC (needs krbtgt hash)
//   - Sapphire Ticket: Use S4U2Self+U2U to get modifiable ticket (any user creds)
//
// # Golden vs Silver vs Diamond vs Sapphire
//
// | Attack   | Requires        | Stealth  | Persistence |
// |----------|-----------------|----------|-------------|
// | Golden   | krbtgt hash     | Medium   | Until 2x krbtgt rotation |
// | Silver   | Service hash    | High     | Until service pwd change |
// | Diamond  | krbtgt hash     | High     | Per-use |
// | Sapphire | Any user creds  | Highest  | Per-use |
//
// Sapphire is unique - it uses legitimate KDC-issued tickets with forged PACs!
package forge
