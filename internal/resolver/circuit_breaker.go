package resolver

import (
	"sync"
	"time"
)

type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

type CircuitBreaker struct {
	state            State
	failures         int
	successes        int
	lastFailureTime  time.Time
	failureThreshold int
	successThreshold int
	openTimeout      time.Duration
	mu               sync.Mutex
	now              func() time.Time
}

type CircuitSnapshot struct {
	State           State
	Failures        int
	Successes       int
	LastFailureTime time.Time
}

func NewCircuitBreaker(failureThreshold, successThreshold int, openTimeout time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if successThreshold <= 0 {
		successThreshold = 2
	}
	if openTimeout <= 0 {
		openTimeout = 30 * time.Second
	}
	return &CircuitBreaker{
		state:            StateClosed,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		openTimeout:      openTimeout,
		now:              time.Now,
	}
}

func (c *CircuitBreaker) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *CircuitBreaker) Allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.state == StateOpen {
		if now.Sub(c.lastFailureTime) >= c.openTimeout {
			c.state = StateHalfOpen
			c.successes = 0
			return true
		}
		return false
	}
	return true
}

func (c *CircuitBreaker) OnSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case StateClosed:
		c.failures = 0
	case StateHalfOpen:
		c.successes++
		if c.successes >= c.successThreshold {
			c.state = StateClosed
			c.failures = 0
			c.successes = 0
		}
	case StateOpen:
		// no-op
	}
}

func (c *CircuitBreaker) OnFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	switch c.state {
	case StateClosed:
		c.failures++
		if c.failures >= c.failureThreshold {
			c.state = StateOpen
			c.lastFailureTime = now
			c.successes = 0
		}
	case StateHalfOpen:
		c.state = StateOpen
		c.lastFailureTime = now
		c.successes = 0
		c.failures = c.failureThreshold
	case StateOpen:
		c.lastFailureTime = now
	}
}

func (c *CircuitBreaker) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *CircuitBreaker) Snapshot() CircuitSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CircuitSnapshot{
		State:           c.state,
		Failures:        c.failures,
		Successes:       c.successes,
		LastFailureTime: c.lastFailureTime,
	}
}

func (c *CircuitBreaker) UpdateConfig(failureThreshold, successThreshold int, openTimeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if failureThreshold > 0 {
		c.failureThreshold = failureThreshold
	}
	if successThreshold > 0 {
		c.successThreshold = successThreshold
	}
	if openTimeout > 0 {
		c.openTimeout = openTimeout
	}
}
