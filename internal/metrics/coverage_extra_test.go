package metrics

import (
	"math"
	"testing"
	"time"
)

func TestObserveUpstreamCircuitStateAndSecurityDropsAppearInSnapshot(t *testing.T) {
	t.Parallel()

	m := New()
	m.ObserveUpstream("1.1.1.1", 10*time.Millisecond)
	m.ObserveUpstream("1.1.1.1", 20*time.Millisecond)
	m.ObserveUpstream("8.8.8.8", 40*time.Millisecond)
	m.SetCircuitState("1.1.1.1", 2)
	m.IncSecurityDrop("rate_limit")
	m.IncSecurityDrop("rate_limit")
	m.IncSecurityDrop("rrl")

	s := m.Snapshot()
	if got := s.CircuitState["1.1.1.1"]; got != 2 {
		t.Fatalf("circuit_state=%d want=2", got)
	}
	if got := s.SecurityDrops["rate_limit"]; got != 2 {
		t.Fatalf("rate_limit drops=%d want=2", got)
	}
	if got := s.SecurityDrops["rrl"]; got != 1 {
		t.Fatalf("rrl drops=%d want=1", got)
	}
	if got := s.UpstreamLatencyMS["1.1.1.1"]; math.Abs(got-15) > 1e-6 {
		t.Fatalf("upstream avg=%f want=15", got)
	}
	if got := s.UpstreamLatencyMS["8.8.8.8"]; math.Abs(got-40) > 1e-6 {
		t.Fatalf("upstream avg=%f want=40", got)
	}
}
