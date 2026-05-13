package resolver

import (
	"strings"

	"dnsresolver/internal/protocol"
)

func InBailiwick(name, zone string) bool {
	n := normalizeFQDN(name)
	z := normalizeFQDN(zone)
	if z == "." {
		return true
	}
	return n == z || strings.HasSuffix(n, "."+strings.TrimSuffix(z, ".")+".") || strings.HasSuffix(n, z)
}

func FilterGlueByBailiwick(zone string, additionals []protocol.ResourceRecord) ([]protocol.ResourceRecord, int) {
	valid := make([]protocol.ResourceRecord, 0, len(additionals))
	rejected := 0
	for _, rr := range additionals {
		if rr.Type != protocol.TypeA && rr.Type != protocol.TypeAAAA {
			continue
		}
		if InBailiwick(rr.Name, zone) {
			valid = append(valid, rr)
		} else {
			rejected++
		}
	}
	return valid, rejected
}

func normalizeFQDN(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}
