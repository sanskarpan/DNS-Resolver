package protocol

import (
	"encoding/binary"
	"fmt"
)

type Header struct {
	ID              uint16 `json:"id"`
	QR              bool   `json:"qr"`
	Opcode          uint8  `json:"opcode"`
	AA              bool   `json:"aa"`
	TC              bool   `json:"tc"`
	RD              bool   `json:"rd"`
	RA              bool   `json:"ra"`
	Z               uint8  `json:"z"`
	RCode           uint8  `json:"rcode"`
	QuestionCount   uint16 `json:"qdcount"`
	AnswerCount     uint16 `json:"ancount"`
	AuthorityCount  uint16 `json:"nscount"`
	AdditionalCount uint16 `json:"arcount"`
}

func (h *Header) decode(data []byte) error {
	if len(data) < HeaderSize {
		return fmt.Errorf("header truncated: have %d need %d", len(data), HeaderSize)
	}
	h.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	h.QR = (flags & 0x8000) != 0
	h.Opcode = uint8((flags >> 11) & 0x0F)
	h.AA = (flags & 0x0400) != 0
	h.TC = (flags & 0x0200) != 0
	h.RD = (flags & 0x0100) != 0
	h.RA = (flags & 0x0080) != 0
	h.Z = uint8((flags >> 4) & 0x07)
	h.RCode = uint8(flags & 0x000F)
	h.QuestionCount = binary.BigEndian.Uint16(data[4:6])
	h.AnswerCount = binary.BigEndian.Uint16(data[6:8])
	h.AuthorityCount = binary.BigEndian.Uint16(data[8:10])
	h.AdditionalCount = binary.BigEndian.Uint16(data[10:12])
	return nil
}

func (h Header) encode() [HeaderSize]byte {
	var out [HeaderSize]byte
	binary.BigEndian.PutUint16(out[0:2], h.ID)
	var flags uint16
	if h.QR {
		flags |= 0x8000
	}
	flags |= uint16(h.Opcode&0x0F) << 11
	if h.AA {
		flags |= 0x0400
	}
	if h.TC {
		flags |= 0x0200
	}
	if h.RD {
		flags |= 0x0100
	}
	if h.RA {
		flags |= 0x0080
	}
	flags |= uint16(h.Z&0x07) << 4
	flags |= uint16(h.RCode & 0x0F)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], h.QuestionCount)
	binary.BigEndian.PutUint16(out[6:8], h.AnswerCount)
	binary.BigEndian.PutUint16(out[8:10], h.AuthorityCount)
	binary.BigEndian.PutUint16(out[10:12], h.AdditionalCount)
	return out
}
