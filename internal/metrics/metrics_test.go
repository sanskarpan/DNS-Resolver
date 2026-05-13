package metrics

import (
	"math"
	"testing"
	"time"
)

func TestSnapshotIncludesQPSWindowsAndActiveConnections(t *testing.T) {
	t.Parallel()
	m := New()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	m.now = func() time.Time { return now }

	now = base.Add(-10 * time.Second)
	m.ObserveQuery("A", "udp", "NOERROR", false, false, 10*time.Millisecond)
	now = base.Add(-2 * time.Minute)
	m.ObserveQuery("A", "udp", "NOERROR", true, false, 12*time.Millisecond)
	now = base.Add(-10 * time.Minute)
	m.ObserveQuery("AAAA", "udp", "NXDOMAIN", false, false, 20*time.Millisecond)

	m.SetActiveConnections("udp", 3)
	m.SetActiveConnections("tcp", 2)
	now = base

	s := m.Snapshot()
	if math.Abs(s.QPS1m-(1.0/60.0)) > 1e-6 {
		t.Fatalf("unexpected qps_1m: %f", s.QPS1m)
	}
	if math.Abs(s.QPS5m-(2.0/300.0)) > 1e-6 {
		t.Fatalf("unexpected qps_5m: %f", s.QPS5m)
	}
	if math.Abs(s.QPS15m-(3.0/900.0)) > 1e-6 {
		t.Fatalf("unexpected qps_15m: %f", s.QPS15m)
	}
	if s.ActiveConnTotal != 5 {
		t.Fatalf("expected active_connections=5, got %d", s.ActiveConnTotal)
	}
	if len(s.TypeDistribution) == 0 || len(s.RCodeDistribution) == 0 {
		t.Fatalf("expected distribution maps to be populated")
	}
}
