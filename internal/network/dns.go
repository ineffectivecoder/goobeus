package network

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// EDUCATIONAL: KDC Discovery via DNS SRV Records
//
// Active Directory uses DNS SRV records to advertise domain controllers.
// The format is: _kerberos._tcp.<domain> or _kerberos._udp.<domain>
//
// Example for CORP.LOCAL:
//   _kerberos._tcp.corp.local. 600 IN SRV 0 100 88 dc01.corp.local.
//   _kerberos._tcp.corp.local. 600 IN SRV 0 100 88 dc02.corp.local.
//
// The record contains:
//   - Priority (0): Lower = preferred
//   - Weight (100): Load balancing within same priority
//   - Port (88): Kerberos default port
//   - Target: FQDN of the KDC
//
// We query these records to find domain controllers without hardcoding.

// KDCInfo contains information about a discovered KDC.
type KDCInfo struct {
	Host     string
	Port     int
	Priority int
	Weight   int
}

// DiscoverKDC finds Kerberos KDCs for a domain via DNS SRV.
//
// EDUCATIONAL: Automatic KDC Discovery
//
// This is how Windows clients find their domain controllers:
// 1. Query _kerberos._tcp.<domain> SRV record
// 2. Sort by priority (lower first), then by weight
// 3. Try each KDC in order until one responds
func DiscoverKDC(domain string) ([]KDCInfo, error) {
	return DiscoverKDCWithContext(context.Background(), domain)
}

// DiscoverKDCWithContext finds KDCs with context support.
func DiscoverKDCWithContext(ctx context.Context, domain string) ([]KDCInfo, error) {
	// Try TCP first (more reliable, handles larger messages)
	srvName := "_kerberos._tcp." + strings.ToLower(domain)

	_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "kerberos", "tcp", domain)
	if err != nil {
		// Try UDP as fallback
		_, addrs, err = net.DefaultResolver.LookupSRV(ctx, "kerberos", "udp", domain)
		if err != nil {
			return nil, fmt.Errorf("failed to discover KDC for %s (tried %s): %w", domain, srvName, err)
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no KDCs found for domain %s", domain)
	}

	kdcs := make([]KDCInfo, len(addrs))
	for i, addr := range addrs {
		kdcs[i] = KDCInfo{
			Host:     strings.TrimSuffix(addr.Target, "."),
			Port:     int(addr.Port),
			Priority: int(addr.Priority),
			Weight:   int(addr.Weight),
		}
	}

	// Sort by priority (lower first), then by weight (higher first)
	sort.Slice(kdcs, func(i, j int) bool {
		if kdcs[i].Priority != kdcs[j].Priority {
			return kdcs[i].Priority < kdcs[j].Priority
		}
		return kdcs[i].Weight > kdcs[j].Weight
	})

	return kdcs, nil
}

// DiscoverKDCHost returns the best KDC hostname for a domain.
func DiscoverKDCHost(domain string) (string, error) {
	kdcs, err := DiscoverKDC(domain)
	if err != nil {
		return "", err
	}
	if len(kdcs) == 0 {
		return "", fmt.Errorf("no KDCs found for domain %s", domain)
	}
	return fmt.Sprintf("%s:%d", kdcs[0].Host, kdcs[0].Port), nil
}

// ResolveKDC returns a KDC address, either from explicit config or discovery.
func ResolveKDC(domain, explicitKDC string) (string, error) {
	if explicitKDC != "" {
		// User provided explicit KDC
		if !strings.Contains(explicitKDC, ":") {
			return explicitKDC + ":88", nil
		}
		return explicitKDC, nil
	}

	// Try DNS discovery
	return DiscoverKDCHost(domain)
}

// LookupSRV is a helper for custom SRV lookups.
func LookupSRV(service, proto, domain string) ([]KDCInfo, error) {
	_, addrs, err := net.LookupSRV(service, proto, domain)
	if err != nil {
		return nil, err
	}

	result := make([]KDCInfo, len(addrs))
	for i, addr := range addrs {
		result[i] = KDCInfo{
			Host:     strings.TrimSuffix(addr.Target, "."),
			Port:     int(addr.Port),
			Priority: int(addr.Priority),
			Weight:   int(addr.Weight),
		}
	}
	return result, nil
}

// DefaultTimeout is the default timeout for KDC operations.
const DefaultTimeout = 30 * time.Second
