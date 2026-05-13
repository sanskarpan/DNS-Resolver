package security

import (
	"crypto/rand"
	"fmt"
	"strings"
)

type CaseRandomizer struct{}

func NewCaseRandomizer() *CaseRandomizer {
	return &CaseRandomizer{}
}

func (c *CaseRandomizer) RandomizeQName(name string) (string, error) {
	if name == "" {
		return name, nil
	}
	bytes := []byte(name)
	mask := make([]byte, len(bytes))
	if _, err := rand.Read(mask); err != nil {
		return "", fmt.Errorf("randomize qname: %w", err)
	}
	for i := range bytes {
		ch := bytes[i]
		if ch >= 'a' && ch <= 'z' {
			if mask[i]&1 == 0 {
				bytes[i] = ch - 32
			}
		}
		if ch >= 'A' && ch <= 'Z' {
			if mask[i]&1 == 1 {
				bytes[i] = ch + 32
			}
		}
	}
	return string(bytes), nil
}

func (c *CaseRandomizer) Matches(sent, received string) bool {
	if sent == "" || received == "" {
		return false
	}
	if len(sent) != len(received) {
		return false
	}
	if !strings.EqualFold(sent, received) {
		return false
	}
	for i := 0; i < len(sent); i++ {
		s := sent[i]
		r := received[i]
		if isLetter(s) && s != r {
			return false
		}
	}
	return true
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
