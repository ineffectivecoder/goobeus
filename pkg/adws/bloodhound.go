package adws

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// EDUCATIONAL: BloodHound Data Collection
//
// Based on LDAPtickler's collectors.go - the definitive reference for BH v5 schema.
// BloodHound uses JSON data files (in a ZIP) with a specific schema for graph analysis.
//
// Full collection includes:
// - users.json - User objects with SPNs, delegation, UAC flags
// - computers.json - Computer objects with LAPS, delegation, OS
// - groups.json - Group objects with membership
// - domains.json - Domain info and trusts
// - ous.json - Organizational Units with GPO links
// - gpos.json - Group Policy Objects
// - containers.json - Container objects
// - certtemplates.json - Certificate templates
// - enterprisecas.json - Enterprise CAs
// - rootcas.json - Root CAs
// - ntauthstores.json - NT Auth Stores

// BHUser represents a user in BloodHound format.
type BHUser struct {
	ObjectID                string         `json:"ObjectIdentifier"`
	PrimaryGroupSID         *string        `json:"PrimaryGroupSID"`
	AllowedToDelegate       []string       `json:"AllowedToDelegate"`
	Properties              map[string]any `json:"Properties"`
	Aces                    []BHAce        `json:"Aces"`
	SPNTargets              []string       `json:"SPNTargets"`
	HasSIDHistory           []string       `json:"HasSIDHistory"`
	IsDeleted               bool           `json:"IsDeleted"`
	DomainSID               string         `json:"DomainSID"`
	UnconstrainedDelegation bool           `json:"UnconstrainedDelegation"`
	IsACLProtected          bool           `json:"IsACLProtected"`
	ContainedBy             *BHContainedBy `json:"ContainedBy"`
}

// BHContainedBy represents the container relationship.
type BHContainedBy struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// BHComputer represents a computer in BloodHound format.
type BHComputer struct {
	ObjectID                string             `json:"ObjectIdentifier"`
	AllowedToAct            []string           `json:"AllowedToAct"`
	PrimaryGroupSID         *string            `json:"PrimaryGroupSID"`
	LocalAdmins             BHCollectionResult `json:"LocalAdmins"`
	PSRemoteUsers           BHCollectionResult `json:"PSRemoteUsers"`
	Properties              map[string]any     `json:"Properties"`
	RemoteDesktopUsers      BHCollectionResult `json:"RemoteDesktopUsers"`
	DcomUsers               BHCollectionResult `json:"DcomUsers"`
	AllowedToDelegate       []string           `json:"AllowedToDelegate"`
	Sessions                BHCollectionResult `json:"Sessions"`
	PrivilegedSessions      BHCollectionResult `json:"PrivilegedSessions"`
	RegistrySessions        BHCollectionResult `json:"RegistrySessions"`
	Aces                    []BHAce            `json:"Aces"`
	HasSIDHistory           []string           `json:"HasSIDHistory"`
	IsDeleted               bool               `json:"IsDeleted"`
	Status                  *string            `json:"Status"`
	IsDC                    bool               `json:"IsDC"`
	UnconstrainedDelegation bool               `json:"UnconstrainedDelegation"`
	DomainSID               string             `json:"DomainSID"`
	IsACLProtected          bool               `json:"IsACLProtected"`
	ContainedBy             *BHContainedBy     `json:"ContainedBy"`
}

// BHCollectionResult represents collection result (sessions, local groups).
type BHCollectionResult struct {
	Collected     bool     `json:"Collected"`
	FailureReason *string  `json:"FailureReason"`
	Results       []string `json:"Results"`
}

// BHGroup represents a group in BloodHound format.
type BHGroup struct {
	ObjectID       string         `json:"ObjectIdentifier"`
	Properties     map[string]any `json:"Properties"`
	Members        []BHMember     `json:"Members"`
	Aces           []BHAce        `json:"Aces"`
	IsDeleted      bool           `json:"IsDeleted"`
	IsACLProtected bool           `json:"IsACLProtected"`
	ContainedBy    *BHContainedBy `json:"ContainedBy"`
	HasSIDHistory  []string       `json:"HasSIDHistory"`
}

// BHMember represents a group member.
type BHMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// BHDomain represents a domain in BloodHound format.
type BHDomain struct {
	ObjectID             string         `json:"ObjectIdentifier"`
	Properties           map[string]any `json:"Properties"`
	Trusts               []string       `json:"Trusts"`
	Aces                 []BHAce        `json:"Aces"`
	Links                []string       `json:"Links"`
	ChildObjects         []string       `json:"ChildObjects"`
	GPOChanges           BHGPOChanges   `json:"GPOChanges"`
	IsDeleted            bool           `json:"IsDeleted"`
	ContainedBy          *BHContainedBy `json:"ContainedBy"`
	ForestRootIdentifier *string        `json:"ForestRootIdentifier"`
	InheritanceHashes    []any          `json:"InheritanceHashes"`
	IsACLProtected       bool           `json:"IsACLProtected"`
}

// BHGPOChanges represents GPO changes.
type BHGPOChanges struct {
	AffectedComputers  []string `json:"AffectedComputers"`
	DcomUsers          []string `json:"DcomUsers"`
	LocalAdmins        []string `json:"LocalAdmins"`
	PSRemoteUsers      []string `json:"PSRemoteUsers"`
	RemoteDesktopUsers []string `json:"RemoteDesktopUsers"`
}

// BHAce represents an ACE.
type BHAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	AceType       string `json:"AceType,omitempty"`
	IsInherited   bool   `json:"IsInherited"`
}

// BloodHoundCollector collects AD data in BloodHound format.
type BloodHoundCollector struct {
	Client     *Client
	Domain     string
	DomainSID  string
	OutputPath string
}

// NewBloodHoundCollector creates a new BloodHound collector.
func NewBloodHoundCollector(client *Client, domain, outputPath string) *BloodHoundCollector {
	return &BloodHoundCollector{
		Client:     client,
		Domain:     strings.ToUpper(domain),
		OutputPath: outputPath,
	}
}

// Collect runs the collection and creates the ZIP file.
func (b *BloodHoundCollector) Collect(ctx context.Context) error {
	fmt.Println("[*] Starting BloodHound collection via ADWS...")
	fmt.Printf("[*] Domain: %s\n", b.Domain)

	timestamp := time.Now().Format("20060102150405")
	zipPath := fmt.Sprintf("%s/%s_bloodhound.zip", b.OutputPath, timestamp)

	// Create ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create ZIP: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Collect and write each data type
	collectors := []struct {
		name string
		fn   func(context.Context, *zip.Writer) error
	}{
		{"computers", b.collectComputers},
		{"users", b.collectUsers},
		{"groups", b.collectGroups},
	}

	for _, c := range collectors {
		fmt.Printf("[*] Collecting %s...\n", c.name)
		if err := c.fn(ctx, zipWriter); err != nil {
			fmt.Printf("[!] %s collection error: %v\n", c.name, err)
		}
	}

	fmt.Printf("[+] BloodHound data written to: %s\n", zipPath)
	fmt.Println("[*] Upload this ZIP to BloodHound for analysis")
	return nil
}

// collectComputers collects computer objects.
func (b *BloodHoundCollector) collectComputers(ctx context.Context, zw *zip.Writer) error {
	computers, err := b.Client.FindComputers(ctx)
	if err != nil {
		return err
	}

	var bhComputers []BHComputer
	for _, comp := range computers {
		props := map[string]any{
			"name":                    comp.SAMAccountName + "@" + b.Domain,
			"domain":                  b.Domain,
			"domainsid":               b.DomainSID,
			"distinguishedname":       comp.DistinguishedName,
			"samaccountname":          comp.SAMAccountName,
			"operatingsystem":         nilIfEmptyStr(comp.OperatingSystem),
			"dnshostname":             nilIfEmptyStr(comp.DNSHostName),
			"description":             nilIfEmptyStr(comp.Description),
			"enabled":                 true,
			"unconstraineddelegation": false,
			"trustedtoauth":           false,
			"isdc":                    comp.IsDC,
			"haslaps":                 false, // Will be updated by LAPS check
		}

		bhComp := BHComputer{
			ObjectID:   comp.DistinguishedName, // Should be SID
			Properties: props,
			IsDC:       comp.IsDC,
			DomainSID:  b.DomainSID,
			LocalAdmins: BHCollectionResult{
				Collected: false,
				Results:   []string{},
			},
			RemoteDesktopUsers: BHCollectionResult{
				Collected: false,
				Results:   []string{},
			},
			DcomUsers: BHCollectionResult{
				Collected: false,
				Results:   []string{},
			},
			PSRemoteUsers: BHCollectionResult{
				Collected: false,
				Results:   []string{},
			},
			Sessions: BHCollectionResult{
				Collected: false,
				Results:   []string{},
			},
			PrivilegedSessions: BHCollectionResult{
				Collected: false,
				Results:   []string{},
			},
			RegistrySessions: BHCollectionResult{
				Collected: false,
				Results:   []string{},
			},
			Aces: []BHAce{},
		}
		bhComputers = append(bhComputers, bhComp)
	}

	return b.writeJSON(zw, "computers.json", map[string]any{
		"data": bhComputers,
		"meta": map[string]any{
			"methods": 0,
			"type":    "computers",
			"count":   len(bhComputers),
			"version": 5,
		},
	})
}

// collectUsers collects user objects.
func (b *BloodHoundCollector) collectUsers(ctx context.Context, zw *zip.Writer) error {
	// Get kerberoastable users (have SPNs)
	spnUsers, _ := b.Client.FindKerberoastable(ctx)
	// Get AS-REP roastable users
	asrepUsers, _ := b.Client.FindASREPRoastable(ctx)

	// Build user map
	userMap := make(map[string]*BHUser)

	for _, u := range spnUsers {
		props := map[string]any{
			"name":                  u.SAMAccountName + "@" + b.Domain,
			"domain":                b.Domain,
			"domainsid":             b.DomainSID,
			"distinguishedname":     u.DistinguishedName,
			"samaccountname":        u.SAMAccountName,
			"description":           nilIfEmptyStr(u.Description),
			"enabled":               true,
			"hasspn":                true,
			"dontreqpreauth":        false,
			"serviceprincipalnames": u.SPNs,
		}

		userMap[u.SAMAccountName] = &BHUser{
			ObjectID:   u.DistinguishedName,
			Properties: props,
			DomainSID:  b.DomainSID,
			SPNTargets: []string{},
			Aces:       []BHAce{},
		}
	}

	for _, u := range asrepUsers {
		if existing, ok := userMap[u.SAMAccountName]; ok {
			existing.Properties["dontreqpreauth"] = true
		} else {
			props := map[string]any{
				"name":              u.SAMAccountName + "@" + b.Domain,
				"domain":            b.Domain,
				"domainsid":         b.DomainSID,
				"distinguishedname": u.DistinguishedName,
				"samaccountname":    u.SAMAccountName,
				"description":       nilIfEmptyStr(u.Description),
				"enabled":           true,
				"hasspn":            false,
				"dontreqpreauth":    true,
			}

			userMap[u.SAMAccountName] = &BHUser{
				ObjectID:   u.DistinguishedName,
				Properties: props,
				DomainSID:  b.DomainSID,
				SPNTargets: []string{},
				Aces:       []BHAce{},
			}
		}
	}

	var bhUsers []BHUser
	for _, u := range userMap {
		bhUsers = append(bhUsers, *u)
	}

	return b.writeJSON(zw, "users.json", map[string]any{
		"data": bhUsers,
		"meta": map[string]any{
			"methods": 0,
			"type":    "users",
			"count":   len(bhUsers),
			"version": 5,
		},
	})
}

// collectGroups collects group objects and memberships.
func (b *BloodHoundCollector) collectGroups(ctx context.Context, zw *zip.Writer) error {
	allGroups := b.Client.FindAllPrivilegedGroups(ctx)

	var bhGroups []BHGroup

	addGroup := func(name string, gr *PrivilegedGroupResult) {
		if gr == nil {
			return
		}

		var members []BHMember
		for _, m := range gr.Members {
			objType := "User"
			if m.ObjectClass == "computer" {
				objType = "Computer"
			} else if m.ObjectClass == "group" {
				objType = "Group"
			}
			members = append(members, BHMember{
				ObjectIdentifier: m.DistinguishedName,
				ObjectType:       objType,
			})
		}

		props := map[string]any{
			"name":              name + "@" + b.Domain,
			"domain":            b.Domain,
			"domainsid":         b.DomainSID,
			"distinguishedname": gr.GroupDN,
			"samaccountname":    strings.ToLower(name),
			"highvalue":         true, // Privileged groups are high value
			"admincount":        true,
		}

		bhGroups = append(bhGroups, BHGroup{
			ObjectID:   gr.GroupDN,
			Properties: props,
			Members:    members,
			Aces:       []BHAce{},
		})
	}

	addGroup("DOMAIN ADMINS", allGroups.DomainAdmins)
	addGroup("ENTERPRISE ADMINS", allGroups.EnterpriseAdmins)
	addGroup("SCHEMA ADMINS", allGroups.SchemaAdmins)
	addGroup("PROTECTED USERS", allGroups.ProtectedUsers)

	return b.writeJSON(zw, "groups.json", map[string]any{
		"data": bhGroups,
		"meta": map[string]any{
			"methods": 0,
			"type":    "groups",
			"count":   len(bhGroups),
			"version": 5,
		},
	})
}

// writeJSON writes a JSON file to the ZIP archive.
func (b *BloodHoundCollector) writeJSON(zw *zip.Writer, filename string, data any) error {
	w, err := zw.Create(filename)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// Helper to return nil for empty strings
func nilIfEmptyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
