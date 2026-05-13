package resolver

import (
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"dnsresolver/internal/protocol"
)

type ResolutionEvent struct {
	QueryID     string            `json:"query_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Step        int               `json:"step"`
	StepType    string            `json:"step_type"`
	Server      string            `json:"server"`
	ServerName  string            `json:"server_name"`
	Query       string            `json:"query"`
	QueryType   string            `json:"query_type"`
	Latency     int64             `json:"latency_ms"`
	Success     bool              `json:"success"`
	RawRequest  []byte            `json:"raw_request"`
	RawResponse []byte            `json:"raw_response"`
	ParsedMsg   *protocol.Message `json:"parsed_message,omitempty"`
	ErrorMsg    string            `json:"error,omitempty"`
}

func (e ResolutionEvent) MarshalJSON() ([]byte, error) {
	type payload struct {
		QueryID     string            `json:"query_id"`
		Timestamp   time.Time         `json:"timestamp"`
		Step        int               `json:"step"`
		StepType    string            `json:"step_type"`
		Server      string            `json:"server"`
		ServerName  string            `json:"server_name"`
		Query       string            `json:"query"`
		QueryType   string            `json:"query_type"`
		Latency     int64             `json:"latency_ms"`
		Success     bool              `json:"success"`
		RawRequest  string            `json:"raw_request"`
		RawResponse string            `json:"raw_response"`
		ParsedMsg   *protocol.Message `json:"parsed_message,omitempty"`
		ErrorMsg    string            `json:"error,omitempty"`
	}
	return json.Marshal(payload{
		QueryID:     e.QueryID,
		Timestamp:   e.Timestamp,
		Step:        e.Step,
		StepType:    e.StepType,
		Server:      e.Server,
		ServerName:  e.ServerName,
		Query:       e.Query,
		QueryType:   e.QueryType,
		Latency:     e.Latency,
		Success:     e.Success,
		RawRequest:  hex.EncodeToString(e.RawRequest),
		RawResponse: hex.EncodeToString(e.RawResponse),
		ParsedMsg:   e.ParsedMsg,
		ErrorMsg:    e.ErrorMsg,
	})
}

type EventHub struct {
	mu          sync.RWMutex
	subscribers map[chan ResolutionEvent]struct{}
}

func NewEventHub() *EventHub {
	return &EventHub{subscribers: make(map[chan ResolutionEvent]struct{})}
}

func (h *EventHub) Subscribe(buffer int) chan ResolutionEvent {
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan ResolutionEvent, buffer)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *EventHub) Unsubscribe(ch chan ResolutionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subscribers[ch]; ok {
		delete(h.subscribers, ch)
		close(ch)
	}
}

func (h *EventHub) Publish(event ResolutionEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}
