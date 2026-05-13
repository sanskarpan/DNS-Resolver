package resolver

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResolutionEventMarshalsRawFieldsAsHex(t *testing.T) {
	t.Parallel()
	ev := ResolutionEvent{
		QueryID:     "q1",
		Timestamp:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Step:        1,
		StepType:    "root_query",
		Server:      "198.41.0.4",
		ServerName:  "a.root-servers.net",
		Query:       "example.com.",
		QueryType:   "A",
		Latency:     12,
		Success:     true,
		RawRequest:  []byte{0xde, 0xad, 0xbe, 0xef},
		RawResponse: []byte{0xca, 0xfe},
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := m["raw_request"]; got != "deadbeef" {
		t.Fatalf("raw_request=%v want=deadbeef", got)
	}
	if got := m["raw_response"]; got != "cafe" {
		t.Fatalf("raw_response=%v want=cafe", got)
	}
}
