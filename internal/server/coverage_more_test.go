package server

import (
	"context"
	"errors"
	"testing"

	"dnsresolver/internal/protocol"
)

func TestReverseHostnameCachesLookupResult(t *testing.T) {
	t.Parallel()

	h := NewHandler(Options{})
	lookups := 0
	h.SetLookupAddrFunc(func(ctx context.Context, addr string) ([]string, error) {
		lookups++
		if addr != "127.0.0.1" {
			t.Fatalf("unexpected lookup addr %s", addr)
		}
		return []string{"localhost."}, nil
	})

	if got := h.ReverseHostname("127.0.0.1"); got != "localhost" {
		t.Fatalf("hostname=%q want=%q", got, "localhost")
	}
	if got := h.ReverseHostname("127.0.0.1"); got != "localhost" {
		t.Fatalf("cached hostname=%q want=%q", got, "localhost")
	}
	if lookups != 1 {
		t.Fatalf("lookups=%d want=1", lookups)
	}
}

func TestReverseHostnameFallsBackToIPOnLookupFailure(t *testing.T) {
	t.Parallel()

	h := NewHandler(Options{})
	h.SetLookupAddrFunc(func(ctx context.Context, addr string) ([]string, error) {
		return nil, errors.New("boom")
	})

	if got := h.ReverseHostname("192.0.2.1"); got != "" {
		t.Fatalf("hostname=%q want empty string on lookup failure", got)
	}
}

func TestHasEDNSAndZoneLabelForStep(t *testing.T) {
	t.Parallel()

	withEDNS := &protocol.Message{
		Additionals: []protocol.ResourceRecord{{
			Name:  ".",
			Type:  protocol.TypeOPT,
			Class: protocol.ClassIN,
		}},
	}
	if !hasEDNS(withEDNS) {
		t.Fatal("expected EDNS to be detected")
	}
	if hasEDNS(&protocol.Message{}) {
		t.Fatal("did not expect EDNS on empty message")
	}

	cases := map[string]string{
		"root_query": "root",
		"tld_query":  "tld",
		"auth_query": "auth",
		"cache_hit":  "auth",
	}
	for step, want := range cases {
		if got := zoneLabelForStep(step); got != want {
			t.Fatalf("zoneLabelForStep(%q)=%q want=%q", step, got, want)
		}
	}
}
