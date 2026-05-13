package protocol

import "fmt"

type Message struct {
	Header      Header           `json:"header"`
	Questions   []Question       `json:"questions,omitempty"`
	Answers     []ResourceRecord `json:"answers,omitempty"`
	Authorities []ResourceRecord `json:"authorities,omitempty"`
	Additionals []ResourceRecord `json:"additionals,omitempty"`
}

func (m *Message) NormalizeCounts() error {
	if len(m.Questions) > 65535 || len(m.Answers) > 65535 || len(m.Authorities) > 65535 || len(m.Additionals) > 65535 {
		return fmt.Errorf("message section too large")
	}
	m.Header.QuestionCount = uint16(len(m.Questions))
	m.Header.AnswerCount = uint16(len(m.Answers))
	m.Header.AuthorityCount = uint16(len(m.Authorities))
	m.Header.AdditionalCount = uint16(len(m.Additionals))
	return nil
}
