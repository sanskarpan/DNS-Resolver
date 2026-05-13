package api

import (
	"testing"

	"dnsresolver/internal/protocol"
)

func TestBuildCompareDiff(t *testing.T) {
	t.Parallel()

	base := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Answers: []protocol.ResourceRecord{
			{
				Name:  "example.com.",
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			},
		},
	}
	diffTTLAndExtra := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Answers: []protocol.ResourceRecord{
			{
				Name:  "example.com.",
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   120,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			},
			{
				Name:  "example.com.",
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{2, 2, 2, 2}},
			},
		},
	}
	rcodeMismatch := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNameError},
	}

	results := []compareResult{
		{Server: "base", RCode: "NOERROR", Answer: base},
		{Server: "server-b", RCode: "NOERROR", Answer: diffTTLAndExtra},
		{Server: "server-c", RCode: "NXDOMAIN", Answer: rcodeMismatch},
		{Server: "server-d", Error: "timeout"},
	}

	diff := buildCompareDiff(results)
	if !diff.Available {
		t.Fatalf("expected diff to be available")
	}
	if diff.BaseServer != "base" {
		t.Fatalf("unexpected base server: %s", diff.BaseServer)
	}
	if len(diff.RCodeMismatches) != 1 || diff.RCodeMismatches[0].Server != "server-c" {
		t.Fatalf("expected one rcode mismatch for server-c, got %+v", diff.RCodeMismatches)
	}
	if len(diff.AnswerDiffs) != 1 || diff.AnswerDiffs[0].Server != "server-b" {
		t.Fatalf("expected one answer diff for server-b, got %+v", diff.AnswerDiffs)
	}
	if len(diff.AnswerDiffs[0].Extra) == 0 {
		t.Fatalf("expected extra records for server-b")
	}
	if len(diff.TTLDiffs) != 1 || diff.TTLDiffs[0].Server != "server-b" {
		t.Fatalf("expected one ttl diff for server-b, got %+v", diff.TTLDiffs)
	}
}

func TestBuildCompareDiffUnavailableWhenNoSuccess(t *testing.T) {
	t.Parallel()
	diff := buildCompareDiff([]compareResult{
		{Server: "a", Error: "timeout"},
		{Server: "b", Error: "refused"},
	})
	if diff.Available {
		t.Fatalf("expected diff to be unavailable")
	}
}
