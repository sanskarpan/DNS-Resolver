package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Encode serializes a DNS Message into wire format.
func Encode(msg *Message) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("message is nil")
	}
	if err := msg.NormalizeCounts(); err != nil {
		return nil, err
	}

	w := &packetWriter{buf: make([]byte, 0, 512)}
	hdr := msg.Header.encode()
	w.WriteBytes(hdr[:])
	compression := map[string]int{}

	for i := range msg.Questions {
		if err := encodeQuestion(w, msg.Questions[i], compression); err != nil {
			return nil, fmt.Errorf("encode question %d: %w", i, err)
		}
	}
	for i := range msg.Answers {
		if err := encodeResourceRecord(w, msg.Answers[i], compression); err != nil {
			return nil, fmt.Errorf("encode answer %d: %w", i, err)
		}
	}
	for i := range msg.Authorities {
		if err := encodeResourceRecord(w, msg.Authorities[i], compression); err != nil {
			return nil, fmt.Errorf("encode authority %d: %w", i, err)
		}
	}
	for i := range msg.Additionals {
		if err := encodeResourceRecord(w, msg.Additionals[i], compression); err != nil {
			return nil, fmt.Errorf("encode additional %d: %w", i, err)
		}
	}
	if len(w.buf) > 65535 {
		return nil, fmt.Errorf("message too large: %d", len(w.buf))
	}
	return w.buf, nil
}

func encodeQuestion(w *packetWriter, q Question, compression map[string]int) error {
	if err := writeName(w, q.Name, compression); err != nil {
		return err
	}
	w.WriteUint16(q.Type)
	w.WriteUint16(q.Class)
	return nil
}

func encodeResourceRecord(w *packetWriter, rr ResourceRecord, compression map[string]int) error {
	if err := writeName(w, rr.Name, compression); err != nil {
		return err
	}
	w.WriteUint16(rr.Type)
	w.WriteUint16(rr.Class)
	w.WriteUint32(rr.TTL)
	lenPos := w.Len()
	w.WriteUint16(0)
	rdataStart := w.Len()
	if err := encodeRData(w, rr.Type, rr.Data, rr.RawRData, compression); err != nil {
		return err
	}
	rdLen := w.Len() - rdataStart
	if rdLen > 65535 {
		return fmt.Errorf("rdata too large: %d", rdLen)
	}
	w.SetUint16(lenPos, uint16(rdLen))
	return nil
}

func writeName(w *packetWriter, raw string, compression map[string]int) error {
	labels, err := splitQName(raw)
	if err != nil {
		return err
	}
	if len(labels) == 0 {
		w.WriteByte(0)
		return nil
	}

	for i := 0; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".") + "."
		key := strings.ToLower(suffix)
		if ptr, ok := compression[key]; ok {
			if ptr > 0x3FFF {
				return fmt.Errorf("compression pointer out of range: %d", ptr)
			}
			w.WriteUint16(uint16(0xC000 | ptr))
			return nil
		}
		compression[key] = w.Len()
		w.WriteByte(byte(len(labels[i])))
		w.WriteBytes([]byte(labels[i]))
	}
	w.WriteByte(0)
	return nil
}

func splitQName(raw string) ([]string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || name == "." {
		return nil, nil
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return nil, nil
	}
	labels := strings.Split(trimmed, ".")
	if len(labels) > MaxLabels {
		return nil, fmt.Errorf("too many labels: %d", len(labels))
	}
	total := 1
	for _, lbl := range labels {
		if lbl == "" {
			return nil, fmt.Errorf("empty label in name %q", raw)
		}
		if len(lbl) > MaxLabelLength {
			return nil, fmt.Errorf("label too long: %d", len(lbl))
		}
		total += len(lbl) + 1
	}
	if total > MaxNameLength {
		return nil, fmt.Errorf("name too long: %d", total)
	}
	return labels, nil
}

type packetWriter struct {
	buf []byte
}

func (w *packetWriter) Len() int {
	return len(w.buf)
}

func (w *packetWriter) WriteByte(v byte) error {
	w.buf = append(w.buf, v)
	return nil
}

func (w *packetWriter) WriteBytes(v []byte) {
	w.buf = append(w.buf, v...)
}

func (w *packetWriter) WriteUint16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *packetWriter) WriteUint32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *packetWriter) SetUint16(pos int, v uint16) {
	binary.BigEndian.PutUint16(w.buf[pos:pos+2], v)
}
