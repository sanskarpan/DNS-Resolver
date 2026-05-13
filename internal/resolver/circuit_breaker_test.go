package resolver

import (
	"os"
	"testing"
)

func TestBlocklistLoadFromFile(t *testing.T) {
	content := "# comment\nexample.com\nads.test.com\n*.wildcard.test"
	tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	bl := NewBlocklist()
	if err := bl.LoadFromFile(tmpFile.Name()); err != nil {
		t.Fatalf("load from file: %v", err)
	}

	if !bl.IsBlocked("example.com.") {
		t.Fatalf("expected example.com blocked")
	}
	if !bl.IsBlocked("ads.test.com.") {
		t.Fatalf("expected ads.test.com blocked")
	}
	if !bl.IsBlocked("sub.wildcard.test.") {
		t.Fatalf("expected sub.wildcard.test blocked")
	}
}

func TestBlocklistLoadFromNonexistentFile(t *testing.T) {
	bl := NewBlocklist()
	err := bl.LoadFromFile("/nonexistent/path/blocklist.txt")
	if err == nil {
		t.Fatalf("expected error for nonexistent file")
	}
}

func TestCircuitBreakerStateTransitions(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 0)

	if cb.State() != StateClosed {
		t.Fatalf("initial state=%d want=closed", cb.State())
	}

	cb.OnFailure()
	cb.OnFailure()
	cb.OnFailure()
	if cb.State() != StateOpen {
		t.Fatalf("after 3 failures state=%d want=open", cb.State())
	}

	if cb.Allow() {
		t.Fatalf("expected allow=false when open")
	}

	cb.mu.Lock()
	cb.state = StateHalfOpen
	cb.mu.Unlock()

	if !cb.Allow() {
		t.Fatalf("expected allow=true when half-open")
	}

	cb.OnFailure()
	if cb.State() != StateOpen {
		t.Fatalf("after failure in half-open state=%d want=open", cb.State())
	}

	cb.mu.Lock()
	cb.state = StateHalfOpen
	cb.mu.Unlock()

	cb.OnSuccess()
	cb.OnSuccess()
	if cb.State() != StateClosed {
		t.Fatalf("after 2 successes state=%d want=closed", cb.State())
	}
}

func TestCircuitBreakerStateString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half_open"},
		{State(99), "unknown"},
	}
	for _, tc := range tests {
		if tc.state.String() != tc.expected {
			t.Errorf("state %d string=%s want=%s", tc.state, tc.state.String(), tc.expected)
		}
	}
}

func TestCircuitBreakerSnapshot(t *testing.T) {
	cb := NewCircuitBreaker(2, 1, 0)
	cb.OnFailure()
	snap := cb.Snapshot()
	if snap.State != StateClosed {
		t.Fatalf("state=%d want=closed", snap.State)
	}
	if snap.Failures != 1 {
		t.Fatalf("failures=%d want=1", snap.Failures)
	}
}
