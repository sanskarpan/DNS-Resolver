package resolver

import (
	"testing"

	"dnsresolver/internal/protocol"
	"dnsresolver/internal/security"
)

func TestValidateResponseQuestion(t *testing.T) {
	t.Parallel()
	cases := security.NewCaseRandomizer()

	tests := []struct {
		name       string
		sentName   string
		sentType   uint16
		case0x20   bool
		message    *protocol.Message
		wantReason string
	}{
		{
			name:       "missing_question",
			sentName:   "example.com.",
			sentType:   protocol.TypeA,
			message:    &protocol.Message{},
			wantReason: "poisoning_question_missing",
		},
		{
			name:     "name_mismatch",
			sentName: "example.com.",
			sentType: protocol.TypeA,
			message: &protocol.Message{
				Questions: []protocol.Question{{Name: "evil.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
			},
			wantReason: "poisoning_name_mismatch",
		},
		{
			name:     "type_mismatch",
			sentName: "example.com.",
			sentType: protocol.TypeA,
			message: &protocol.Message{
				Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeAAAA, Class: protocol.ClassIN}},
			},
			wantReason: "poisoning_question_mismatch",
		},
		{
			name:     "case_mismatch",
			sentName: "ExAmple.com.",
			sentType: protocol.TypeA,
			case0x20: true,
			message: &protocol.Message{
				Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
			},
			wantReason: "poisoning_case_mismatch",
		},
		{
			name:     "valid",
			sentName: "ExAmple.com.",
			sentType: protocol.TypeA,
			case0x20: true,
			message: &protocol.Message{
				Questions: []protocol.Question{{Name: "ExAmple.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
			},
			wantReason: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reason, err := validateResponseQuestion(tt.sentName, tt.sentType, tt.case0x20, tt.message, cases)
			if tt.wantReason == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error")
			}
			if reason != tt.wantReason {
				t.Fatalf("reason=%s want=%s", reason, tt.wantReason)
			}
		})
	}
}
