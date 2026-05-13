package protocol

import "testing"

func FuzzDecode(f *testing.F) {
	valid := &Message{
		Header:    Header{ID: 1, QR: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers:   []ResourceRecord{{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 60, Data: AData{Address: [4]byte{1, 2, 3, 4}}}},
	}
	validWire, _ := Encode(valid)

	malformedPointer := []byte{
		0x00, 0x01, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xC0, 0xFF,
		0x00, 0x01,
		0x00, 0x01,
	}

	f.Add(validWire)
	f.Add(malformedPointer)
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Decode(data)
		if err != nil {
			return
		}
		_, _ = Encode(msg)
	})
}
