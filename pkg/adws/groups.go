package adws

import (
	"context"
	"fmt"
)

// EDUCATIONAL: Privileged Group Enumeration
//
// Identifying members of privileged groups is critical for:
// 1. Understanding the attack surface
// 2. Prioritizing targets
// 3. Mapping admin paths
//
// Key privileged groups:
// - Domain Admins (RID 512) - Full domain control
// - Enterprise Admins (RID 519) - Forest-wide control
// - Schema Admins (RID 518) - Can modify AD schema
// - Administrators (RID 544) - Builtin admin group
// - Account Operators (RID 548) - Can create/modify accounts
// - Backup Operators (RID 551) - Can backup/restore DC
// - Protected Users - Members have extra protections

// GroupMember represents a member of a group.
type GroupMember struct {
	SAMAccountName    string
	DistinguishedName string
	ObjectClass       string // user, computer, group
	Description       string
	Enabled           bool
}

// PrivilegedGroupResult represents a privileged group and its members.
type PrivilegedGroupResult struct {
	GroupName    string
	GroupDN      string
	MemberCount  int
	Members      []GroupMember
	NestedGroups []string // Groups that are members
}

// FindDomainAdmins returns members of Domain Admins.
//
// EDUCATIONAL: Domain Admins
//
// Domain Admins have full control over the domain. Members can:
// - Create/delete any object
// - Modify any attribute
// - Access any resource
// - Login to any machine
func (c *Client) FindDomainAdmins(ctx context.Context) (*PrivilegedGroupResult, error) {
	return c.FindGroupMembers(ctx, "Domain Admins")
}

// FindEnterpriseAdmins returns members of Enterprise Admins.
//
// EDUCATIONAL: Enterprise Admins
//
// Enterprise Admins exist only in the forest root domain but have
// full control across ALL domains in the forest.
func (c *Client) FindEnterpriseAdmins(ctx context.Context) (*PrivilegedGroupResult, error) {
	return c.FindGroupMembers(ctx, "Enterprise Admins")
}

// FindSchemaAdmins returns members of Schema Admins.
func (c *Client) FindSchemaAdmins(ctx context.Context) (*PrivilegedGroupResult, error) {
	return c.FindGroupMembers(ctx, "Schema Admins")
}

// FindProtectedUsers returns members of Protected Users.
//
// EDUCATIONAL: Protected Users Group
//
// Members have additional security:
// - No NTLM authentication
// - No DES/RC4 in Kerberos pre-auth
// - Shorter TGT lifetime (4 hours)
// - No caching of plaintext credentials
func (c *Client) FindProtectedUsers(ctx context.Context) (*PrivilegedGroupResult, error) {
	return c.FindGroupMembers(ctx, "Protected Users")
}

// FindGroupMembers returns members of a specified group.
func (c *Client) FindGroupMembers(ctx context.Context, groupName string) (*PrivilegedGroupResult, error) {
	// First, find the group
	groupFilter := fmt.Sprintf(`(&(objectClass=group)(sAMAccountName=%s))`, groupName)

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>member</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, groupFilter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("group enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	if len(objects) == 0 {
		return nil, fmt.Errorf("group not found: %s", groupName)
	}

	group := objects[0]
	result := &PrivilegedGroupResult{
		GroupName: groupName,
		GroupDN:   group.DN,
	}

	// Get members from the group
	if members, ok := group.RawAttributes["member"]; ok {
		result.MemberCount = len(members)

		// Query each member for details
		for _, memberDN := range members {
			member, err := c.getObjectByDN(ctx, memberDN)
			if err != nil {
				continue // Skip if we can't read the member
			}

			gm := GroupMember{
				SAMAccountName:    member.SAMAccountName,
				DistinguishedName: memberDN,
				Description:       member.Description,
			}

			// Determine object type
			for _, oc := range member.ObjectClass {
				if oc == "user" {
					gm.ObjectClass = "user"
					break
				} else if oc == "computer" {
					gm.ObjectClass = "computer"
					break
				} else if oc == "group" {
					gm.ObjectClass = "group"
					result.NestedGroups = append(result.NestedGroups, memberDN)
					break
				}
			}

			// Check if enabled (UAC flag 2 = ACCOUNTDISABLE)
			gm.Enabled = (member.UserAccountControl & 2) == 0

			result.Members = append(result.Members, gm)
		}
	}

	return result, nil
}

// getObjectByDN retrieves an object by its DN.
func (c *Client) getObjectByDN(ctx context.Context, dn string) (*ADObject, error) {
	filter := fmt.Sprintf(`(distinguishedName=%s)`, dn)

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>objectClass</ad:Path>
        <ad:Path>description</ad:Path>
        <ad:Path>userAccountControl</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, err
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, err
	}

	if len(objects) == 0 {
		return nil, fmt.Errorf("object not found")
	}

	return &objects[0], nil
}

// AllPrivilegedGroups holds results for all privileged groups.
type AllPrivilegedGroups struct {
	DomainAdmins     *PrivilegedGroupResult
	EnterpriseAdmins *PrivilegedGroupResult
	SchemaAdmins     *PrivilegedGroupResult
	ProtectedUsers   *PrivilegedGroupResult
	Errors           []string
}

// FindAllPrivilegedGroups enumerates all major privileged groups.
func (c *Client) FindAllPrivilegedGroups(ctx context.Context) *AllPrivilegedGroups {
	result := &AllPrivilegedGroups{}

	if da, err := c.FindDomainAdmins(ctx); err == nil {
		result.DomainAdmins = da
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("Domain Admins: %v", err))
	}

	if ea, err := c.FindEnterpriseAdmins(ctx); err == nil {
		result.EnterpriseAdmins = ea
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("Enterprise Admins: %v", err))
	}

	if sa, err := c.FindSchemaAdmins(ctx); err == nil {
		result.SchemaAdmins = sa
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("Schema Admins: %v", err))
	}

	if pu, err := c.FindProtectedUsers(ctx); err == nil {
		result.ProtectedUsers = pu
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("Protected Users: %v", err))
	}

	return result
}
