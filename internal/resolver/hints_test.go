package resolver

import (
	"testing"

	"dnsresolver/internal/protocol"
)

func TestHints(t *testing.T) {
	hints := DefaultRootHints()
	if len(hints) != 13 {
		t.Fatalf("expected 13 root hints, got %d", len(hints))
	}

	ips := RootHintIPs()
	if len(ips) != 13 {
		t.Fatalf("expected 13 root IPs, got %d", len(ips))
	}

	for _, ip := range ips {
		if ip == "" {
			t.Fatalf("expected non-empty IP")
		}
	}
}

func TestQNAMEMinimizationSteps(t *testing.T) {
	steps := QNAMEMinimizationSteps("www.example.com.")
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps for www.example.com., got %d", len(steps))
	}
	if steps[0] != "com." {
		t.Fatalf("expected step 0 to be com., got %s", steps[0])
	}
	if steps[1] != "example.com." {
		t.Fatalf("expected step 1 to be example.com., got %s", steps[1])
	}
	if steps[2] != "www.example.com." {
		t.Fatalf("expected step 2 to be www.example.com., got %s", steps[2])
	}
}

func TestQNAMEMinimizationStepsRoot(t *testing.T) {
	steps := QNAMEMinimizationSteps(".")
	if len(steps) != 1 {
		t.Fatalf("expected 1 step for root, got %d", len(steps))
	}
}

func TestMinimizedQNameForHop(t *testing.T) {
	tests := []struct {
		qname string
		hop   int
		want  string
	}{
		{"www.example.com.", 0, "com."},
		{"www.example.com.", 1, "example.com."},
		{"www.example.com.", 2, "www.example.com."},
		{"www.example.com.", 3, "www.example.com."},
		{"example.com.", 0, "com."},
		{"example.com.", 1, "example.com."},
		{"a.b.c.d.example.com.", 0, "com."},
		{"a.b.c.d.example.com.", 1, "example.com."},
		{"a.b.c.d.example.com.", 2, "d.example.com."},
	}

	for _, tc := range tests {
		got := MinimizedQNameForHop(tc.qname, tc.hop)
		if got != tc.want {
			t.Errorf("MinimizedQNameForHop(%q, %d)=%q want=%q", tc.qname, tc.hop, got, tc.want)
		}
	}
}

func TestNormalizeFQDN(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"EXAMPLE.COM", "example.com."},
		{"EXAMPLE.COM.", "example.com."},
		{"Example.Com", "example.com."},
		{".", "."},
		{"", "."},
	}

	for _, tc := range tests {
		got := normalizeFQDN(tc.input)
		if got != tc.want {
			t.Errorf("normalizeFQDN(%q)=%q want=%q", tc.input, got, tc.want)
		}
	}
}

func TestInBailiwick(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected bool
	}{
		{"ns1.example.com.", "example.com.", true},
		{"www.example.com.", "example.com.", true},
		{"example.com.", "example.com.", true},
		{"other.com.", "example.com.", false},
		{"sub.other.com.", "example.com.", false},
		{"example.org.", "example.com.", false},
		{"ns1.example.com.", "com.", true},
		{"ns1.example.org.", "com.", false},
	}

	for _, tc := range tests {
		got := InBailiwick(tc.name, tc.zone)
		if got != tc.expected {
			t.Errorf("InBailiwick(%q, %q)=%v want=%v", tc.name, tc.zone, got, tc.expected)
		}
	}
}

func TestFilterGlueByBailiwick(t *testing.T) {
	records := []protocol.ResourceRecord{
		{Name: "ns1.example.com.", Type: protocol.TypeA, Data: protocol.AData{Address: [4]byte{1, 1, 1, 1}}},
		{Name: "ns2.example.com.", Type: protocol.TypeA, Data: protocol.AData{Address: [4]byte{2, 2, 2, 2}}},
		{Name: "ns1.other.com.", Type: protocol.TypeA, Data: protocol.AData{Address: [4]byte{3, 3, 3, 3}}},
		{Name: "ns1.example.org.", Type: protocol.TypeA, Data: protocol.AData{Address: [4]byte{4, 4, 4, 4}}},
	}

	valid, rejected := FilterGlueByBailiwick("example.com.", records)
	if len(valid) != 2 {
		t.Fatalf("expected 2 valid records, got %d", len(valid))
	}
	if rejected != 2 {
		t.Fatalf("expected 2 rejected records, got %d", rejected)
	}
}
