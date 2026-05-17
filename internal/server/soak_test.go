package server

import (
	"context"
	"net"
	"sync"
	"testing"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
)

func TestHandlerSustainsConcurrentQueryBurst(t *testing.T) {
	t.Parallel()

	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  "burst.example.",
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			}},
		}, nil, nil
	})

	h := NewHandler(Options{
		Resolver:   r,
		Metrics:    metrics.New(),
		Prometheus: metrics.NewPrometheus(),
		MaxUDPSize: 4096,
	})

	const workers = 24
	const queriesPerWorker = 40

	var wg sync.WaitGroup
	errCh := make(chan error, workers*queriesPerWorker)

	for worker := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < queriesPerWorker; i++ {
				msg := &protocol.Message{
					Header: protocol.Header{ID: uint16(worker*queriesPerWorker + i + 1), RD: true},
					Questions: []protocol.Question{{
						Name:  "burst.example.",
						Type:  protocol.TypeA,
						Class: protocol.ClassIN,
					}},
				}
				wire, err := protocol.Encode(msg)
				if err != nil {
					errCh <- err
					return
				}
				respWire, drop, err := h.HandlePacket(context.Background(), wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54000 + worker}, "udp")
				if err != nil {
					errCh <- err
					return
				}
				if drop {
					errCh <- errDropped
					return
				}
				resp, err := protocol.Decode(respWire)
				if err != nil {
					errCh <- err
					return
				}
				if resp.Header.RCode != protocol.RCodeNoError || len(resp.Answers) == 0 {
					errCh <- errInvalidBurstResponse
					return
				}
			}
		}(worker)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent burst failed: %v", err)
		}
	}
	snapshot := h.Metrics().Snapshot()
	if got := snapshot.TotalQueries; got != uint64(workers*queriesPerWorker) {
		t.Fatalf("total_queries=%d want=%d", got, workers*queriesPerWorker)
	}
}

var (
	errDropped              = soakError("unexpected packet drop")
	errInvalidBurstResponse = soakError("unexpected response payload")
)

type soakError string

func (e soakError) Error() string { return string(e) }
