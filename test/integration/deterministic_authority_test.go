package integration

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestIntegrationDeterministicReferralWalk(t *testing.T) {
	port := reservePort(t)
	dnsAddr := "127.0.0.1:" + strconv.Itoa(port)

	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{})
	r := resolver.New(cfg, c)
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		stepType := "auth_query"
		if step == 1 {
			stepType = "root_query"
		} else if step == 2 {
			stepType = "tld_query"
		}
		ev := resolver.ResolutionEvent{
			QueryID:   queryID,
			Timestamp: time.Now().UTC(),
			Step:      step,
			StepType:  stepType,
			Query:     qname,
			QueryType: protocol.TypeToString(qtype),
			Success:   true,
		}
		events := []resolver.ResolutionEvent{ev}

		switch step {
		case 1:
			return integrationReferral("com.", "ns1.com.", [4]byte{1, 1, 1, 1}), events, nil
		case 2:
			return integrationReferral("example.com.", "ns1.example.com.", [4]byte{2, 2, 2, 2}), events, nil
		case 3:
			return answerA("example.com.", [4]byte{93, 184, 216, 34}), events, nil
		default:
			return nil, nil, fmt.Errorf("unexpected step %d", step)
		}
	})

	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, MaxUDPSize: 4096, Metrics: m, Prometheus: p, RRLEnabled: false})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udp := server.NewUDPServer(dnsAddr, h, 16)
	if err := udp.Start(ctx); err != nil {
		t.Fatalf("udp start: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = udp.Shutdown(shutdownCtx)
	}()

	req := makeQuery(t, "example.com.", protocol.TypeA, true)
	resp := sendUDPQuery(t, dnsAddr, req)
	msg, err := protocol.Decode(resp)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Header.RCode != protocol.RCodeNoError || len(msg.Answers) == 0 {
		t.Fatalf("unexpected dns response: rcode=%d answers=%d", msg.Header.RCode, len(msg.Answers))
	}

	history := r.History(1, 1)
	if len(history) != 1 {
		t.Fatalf("expected one history entry, got %d", len(history))
	}
	trace := r.Trace(history[0].QueryID)
	seen := map[string]bool{}
	for _, ev := range trace {
		seen[ev.StepType] = true
	}
	for _, step := range []string{"root_query", "tld_query", "auth_query"} {
		if !seen[step] {
			t.Fatalf("expected trace to include %s step, trace=%+v", step, trace)
		}
	}
}

func integrationReferral(zone, ns string, ip [4]byte) *protocol.Message {
	return &protocol.Message{
		Header:      protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Authorities: []protocol.ResourceRecord{{Name: zone, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 60, Data: protocol.NSData{Name: ns}}},
		Additionals: []protocol.ResourceRecord{{Name: ns, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: ip}}},
	}
}
