package protocol

import (
	"encoding/binary"
	"fmt"
)

// Decode parses wire-format DNS bytes into a DNS Message.
func Decode(packet []byte) (*Message, error) {
	if len(packet) < HeaderSize {
		return nil, fmt.Errorf("packet too small: %d", len(packet))
	}
	if len(packet) > MaxDNSPacketLen {
		return nil, fmt.Errorf("packet exceeds max size: %d", len(packet))
	}

	msg := &Message{}
	if err := msg.Header.decode(packet[:HeaderSize]); err != nil {
		return nil, err
	}
	off := HeaderSize

	for i := 0; i < int(msg.Header.QuestionCount); i++ {
		q, next, err := decodeQuestion(packet, off)
		if err != nil {
			return nil, fmt.Errorf("decode question %d: %w", i, err)
		}
		msg.Questions = append(msg.Questions, q)
		off = next
	}
	for i := 0; i < int(msg.Header.AnswerCount); i++ {
		rr, next, err := decodeResourceRecord(packet, off)
		if err != nil {
			return nil, fmt.Errorf("decode answer %d: %w", i, err)
		}
		msg.Answers = append(msg.Answers, rr)
		off = next
	}
	for i := 0; i < int(msg.Header.AuthorityCount); i++ {
		rr, next, err := decodeResourceRecord(packet, off)
		if err != nil {
			return nil, fmt.Errorf("decode authority %d: %w", i, err)
		}
		msg.Authorities = append(msg.Authorities, rr)
		off = next
	}
	for i := 0; i < int(msg.Header.AdditionalCount); i++ {
		rr, next, err := decodeResourceRecord(packet, off)
		if err != nil {
			return nil, fmt.Errorf("decode additional %d: %w", i, err)
		}
		msg.Additionals = append(msg.Additionals, rr)
		off = next
	}

	if off > len(packet) {
		return nil, fmt.Errorf("decode overflow: offset=%d len=%d", off, len(packet))
	}

	return msg, nil
}

func decodeQuestion(data []byte, off int) (Question, int, error) {
	name, next, err := decodeName(data, off)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(data) {
		return Question{}, 0, fmt.Errorf("question truncated")
	}
	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[next : next+2]),
		Class: binary.BigEndian.Uint16(data[next+2 : next+4]),
	}
	return q, next + 4, nil
}

func decodeResourceRecord(data []byte, off int) (ResourceRecord, int, error) {
	name, next, err := decodeName(data, off)
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	if next+10 > len(data) {
		return ResourceRecord{}, 0, fmt.Errorf("resource record header truncated")
	}

	typ := binary.BigEndian.Uint16(data[next : next+2])
	class := binary.BigEndian.Uint16(data[next+2 : next+4])
	ttl := binary.BigEndian.Uint32(data[next+4 : next+8])
	rdLen := int(binary.BigEndian.Uint16(data[next+8 : next+10]))
	rdStart := next + 10
	rdEnd := rdStart + rdLen
	if rdEnd > len(data) {
		return ResourceRecord{}, 0, fmt.Errorf("rdata truncated")
	}

	rr := ResourceRecord{
		Name:     name,
		Type:     typ,
		Class:    class,
		TTL:      ttl,
		RawRData: append([]byte(nil), data[rdStart:rdEnd]...),
	}
	if typ == TypeOPT {
		rr.Data = OPTData{
			UDPSize:  class,
			ExtRCode: uint8((ttl >> 24) & 0xFF),
			Version:  uint8((ttl >> 16) & 0xFF),
			Flags:    uint16(ttl & 0xFFFF),
			Options:  append([]byte(nil), data[rdStart:rdEnd]...),
		}
		return rr, rdEnd, nil
	}

	rdata, err := parseRData(data, rdStart, rdLen, typ)
	if err == nil {
		rr.Data = rdata
	}
	return rr, rdEnd, nil
}

func decodeName(data []byte, off int) (string, int, error) {
	if off >= len(data) {
		return "", 0, fmt.Errorf("name offset out of range: %d", off)
	}
	labels := make([]string, 0, 4)
	visited := map[int]struct{}{}
	curr := off
	next := -1
	jumps := 0

	for {
		if curr >= len(data) {
			return "", 0, fmt.Errorf("name truncated")
		}
		b := data[curr]
		switch b & 0xC0 {
		case 0xC0:
			if curr+1 >= len(data) {
				return "", 0, fmt.Errorf("pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(data[curr:curr+2]) & 0x3FFF)
			if ptr >= len(data) {
				return "", 0, fmt.Errorf("invalid pointer offset: %d", ptr)
			}
			if _, ok := visited[ptr]; ok {
				return "", 0, fmt.Errorf("compression pointer loop")
			}
			visited[ptr] = struct{}{}
			if next == -1 {
				next = curr + 2
			}
			curr = ptr
			jumps++
			if jumps > MaxLabels {
				return "", 0, fmt.Errorf("too many compression jumps")
			}
		case 0x00:
			if b == 0 {
				if next == -1 {
					next = curr + 1
				}
				name, err := joinLabels(labels)
				if err != nil {
					return "", 0, err
				}
				return name, next, nil
			}
			labelLen := int(b)
			if labelLen > MaxLabelLength {
				return "", 0, fmt.Errorf("label too long: %d", labelLen)
			}
			if labelLen == 0 {
				if next == -1 {
					next = curr + 1
				}
				name, err := joinLabels(labels)
				if err != nil {
					return "", 0, err
				}
				return name, next, nil
			}
			curr++
			if curr+labelLen > len(data) {
				return "", 0, fmt.Errorf("label truncated")
			}
			labels = append(labels, string(data[curr:curr+labelLen]))
			if len(labels) > MaxLabels {
				return "", 0, fmt.Errorf("too many labels")
			}
			curr += labelLen
		default:
			return "", 0, fmt.Errorf("invalid label prefix: 0x%x", b)
		}
	}
}

func joinLabels(labels []string) (string, error) {
	if len(labels) == 0 {
		return ".", nil
	}
	total := 1 // trailing dot
	for _, lbl := range labels {
		total += len(lbl) + 1
	}
	if total > MaxNameLength {
		return "", fmt.Errorf("name exceeds max length: %d", total)
	}
	name := ""
	for i, lbl := range labels {
		if i > 0 {
			name += "."
		}
		name += lbl
	}
	return name + ".", nil
}
