package protocol

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestTypeToString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		typ  uint16
		want string
	}{
		{TypeA, "A"},
		{TypeAAAA, "AAAA"},
		{TypeCNAME, "CNAME"},
		{TypeMX, "MX"},
		{TypeNS, "NS"},
		{TypeSOA, "SOA"},
		{TypeTXT, "TXT"},
		{TypePTR, "PTR"},
		{TypeSRV, "SRV"},
		{TypeOPT, "OPT"},
		{TypeDS, "DS"},
		{TypeRRSIG, "RRSIG"},
		{TypeNSEC, "NSEC"},
		{TypeDNSKEY, "DNSKEY"},
		{TypeNSEC3, "NSEC3"},
		{TypeCAA, "CAA"},
		{TypeANY, "ANY"},
		{999, "TYPE999"},
	}
	for _, tc := range tests {
		got := TypeToString(tc.typ)
		if got != tc.want {
			t.Errorf("TypeToString(%d)=%s want=%s", tc.typ, got, tc.want)
		}
	}
}

func TestRCodeToString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code uint8
		want string
	}{
		{RCodeNoError, "NOERROR"},
		{RCodeFormatError, "FORMERR"},
		{RCodeServerFailure, "SERVFAIL"},
		{RCodeNameError, "NXDOMAIN"},
		{RCodeNotImplemented, "NOTIMP"},
		{RCodeRefused, "REFUSED"},
		{99, "RCODE99"},
	}
	for _, tc := range tests {
		got := RCodeToString(tc.code)
		if got != tc.want {
			t.Errorf("RCodeToString(%d)=%s want=%s", tc.code, got, tc.want)
		}
	}
}

func TestEncodeDecodeRoundTripRecordTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rr   ResourceRecord
	}{
		{name: "A", rr: ResourceRecord{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300, Data: AData{Address: [4]byte{1, 2, 3, 4}}}},
		{name: "AAAA", rr: ResourceRecord{Name: "example.com.", Type: TypeAAAA, Class: ClassIN, TTL: 300, Data: AAAAData{Address: [16]byte{0x20, 0x01, 0x0d, 0xb8, 1}}}},
		{name: "CNAME", rr: ResourceRecord{Name: "www.example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 300, Data: CNAMEData{Name: "example.com."}}},
		{name: "MX", rr: ResourceRecord{Name: "example.com.", Type: TypeMX, Class: ClassIN, TTL: 300, Data: MXData{Preference: 10, Exchange: "mail.example.com."}}},
		{name: "NS", rr: ResourceRecord{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 300, Data: NSData{Name: "ns1.example.com."}}},
		{name: "SOA", rr: ResourceRecord{Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 300, Data: SOAData{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5}}},
		{name: "TXT", rr: ResourceRecord{Name: "example.com.", Type: TypeTXT, Class: ClassIN, TTL: 300, Data: TXTData{Texts: []string{"hello", "world"}}}},
		{name: "PTR", rr: ResourceRecord{Name: "4.3.2.1.in-addr.arpa.", Type: TypePTR, Class: ClassIN, TTL: 300, Data: PTRData{Name: "host.example.com."}}},
		{name: "SRV", rr: ResourceRecord{Name: "_sip._tcp.example.com.", Type: TypeSRV, Class: ClassIN, TTL: 300, Data: SRVData{Priority: 1, Weight: 2, Port: 443, Target: "svc.example.com."}}},
		{name: "CAA", rr: ResourceRecord{Name: "example.com.", Type: TypeCAA, Class: ClassIN, TTL: 300, Data: CAAData{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			msg := &Message{
				Header:    Header{ID: 1234, RD: true, QR: true, RA: true},
				Questions: []Question{{Name: tc.rr.Name, Type: tc.rr.Type, Class: ClassIN}},
				Answers:   []ResourceRecord{tc.rr},
			}
			wire, err := Encode(msg)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			decoded, err := Decode(wire)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if len(decoded.Answers) != 1 {
				t.Fatalf("answers=%d", len(decoded.Answers))
			}
			got := decoded.Answers[0]
			if got.Type != tc.rr.Type || got.Class != tc.rr.Class || got.TTL != tc.rr.TTL || got.Name != tc.rr.Name {
				t.Fatalf("rr meta mismatch: got=%+v want=%+v", got, tc.rr)
			}
			if !reflect.DeepEqual(got.Data, tc.rr.Data) {
				t.Fatalf("rdata mismatch: got=%#v want=%#v", got.Data, tc.rr.Data)
			}
		})
	}
}

func TestNameCompressionPointerChain(t *testing.T) {
	t.Parallel()
	msg := &Message{
		Header: Header{ID: 1, QR: true},
		Questions: []Question{
			{Name: "a.example.com.", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{Name: "a.example.com.", Type: TypeA, Class: ClassIN, TTL: 60, Data: AData{Address: [4]byte{1, 1, 1, 1}}},
			{Name: "b.example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: CNAMEData{Name: "a.example.com."}},
		},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Contains(wire, []byte{0xC0}) {
		t.Fatalf("expected compression pointer in encoded message")
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.Answers) != 2 {
		t.Fatalf("answers=%d", len(decoded.Answers))
	}
}

func TestDecodeMalformedPackets(t *testing.T) {
	t.Parallel()

	_, err := Decode([]byte{0x00})
	if err == nil {
		t.Fatalf("expected error for truncated header")
	}

	// Invalid pointer offset in question name.
	invalidPtr := make([]byte, HeaderSize+6)
	binary.BigEndian.PutUint16(invalidPtr[4:6], 1)
	invalidPtr[HeaderSize] = 0xC0
	invalidPtr[HeaderSize+1] = 0xFF
	binary.BigEndian.PutUint16(invalidPtr[HeaderSize+2:HeaderSize+4], TypeA)
	binary.BigEndian.PutUint16(invalidPtr[HeaderSize+4:HeaderSize+6], ClassIN)
	_, err = Decode(invalidPtr)
	if err == nil {
		t.Fatalf("expected invalid pointer error")
	}

	// Circular pointer name.
	circular := make([]byte, HeaderSize+6)
	binary.BigEndian.PutUint16(circular[4:6], 1)
	circular[HeaderSize] = 0xC0
	circular[HeaderSize+1] = byte(HeaderSize)
	binary.BigEndian.PutUint16(circular[HeaderSize+2:HeaderSize+4], TypeA)
	binary.BigEndian.PutUint16(circular[HeaderSize+4:HeaderSize+6], ClassIN)
	_, err = Decode(circular)
	if err == nil {
		t.Fatalf("expected circular pointer error")
	}

	// Label length overflow.
	labelOverflow := make([]byte, HeaderSize+6)
	binary.BigEndian.PutUint16(labelOverflow[4:6], 1)
	labelOverflow[HeaderSize] = 64
	labelOverflow[HeaderSize+1] = 0
	binary.BigEndian.PutUint16(labelOverflow[HeaderSize+2:HeaderSize+4], TypeA)
	binary.BigEndian.PutUint16(labelOverflow[HeaderSize+4:HeaderSize+6], ClassIN)
	_, err = Decode(labelOverflow)
	if err == nil {
		t.Fatalf("expected label overflow error")
	}
}

func TestBigEndianEncoding(t *testing.T) {
	t.Parallel()
	msg := &Message{
		Header:    Header{ID: 0x1234, RD: true, QuestionCount: 1},
		Questions: []Question{{Name: "example.com.", Type: 0xABCD, Class: 0xEEFF}},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if wire[0] != 0x12 || wire[1] != 0x34 {
		t.Fatalf("header id not big endian: %x", wire[0:2])
	}
	if wire[len(wire)-4] != 0xAB || wire[len(wire)-3] != 0xCD {
		t.Fatalf("qtype not big endian: %x", wire[len(wire)-4:len(wire)-2])
	}
	if wire[len(wire)-2] != 0xEE || wire[len(wire)-1] != 0xFF {
		t.Fatalf("qclass not big endian: %x", wire[len(wire)-2:])
	}
}

func TestNameValidationLimits(t *testing.T) {
	t.Parallel()

	maxLabel := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := splitQName(maxLabel + ".com."); err != nil {
		t.Fatalf("expected max label length to pass: %v", err)
	}

	tooLongLabel := maxLabel + "a"
	if _, err := splitQName(tooLongLabel + ".com."); err == nil {
		t.Fatalf("expected too-long label to fail")
	}

	longName := ""
	for i := 0; i < 40; i++ {
		longName += "aaaaaa."
	}
	if _, err := splitQName(longName); err == nil {
		t.Fatalf("expected too-long full name to fail")
	}
}

func TestDecodeAllowsLargeTCPMessage(t *testing.T) {
	t.Parallel()

	chunks := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		chunks = append(chunks, strings.Repeat("x", 200))
	}
	msg := &Message{
		Header:    Header{ID: 7, QR: true, RD: true, RA: true},
		Questions: []Question{{Name: "large.example.com.", Type: TypeTXT, Class: ClassIN}},
		Answers: []ResourceRecord{{
			Name:  "large.example.com.",
			Type:  TypeTXT,
			Class: ClassIN,
			TTL:   60,
			Data:  TXTData{Texts: chunks},
		}},
	}

	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(wire) <= MaxUDPPacketLen {
		t.Fatalf("expected message > UDP size, got %d", len(wire))
	}

	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode large message: %v", err)
	}
	if len(decoded.Answers) != 1 {
		t.Fatalf("answers=%d want=1", len(decoded.Answers))
	}
}

func BenchmarkDecodeARecord(b *testing.B) {
	msg := &Message{
		Header:    Header{ID: 1, QR: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers:   []ResourceRecord{{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 60, Data: AData{Address: [4]byte{8, 8, 8, 8}}}},
	}
	wire, err := Encode(msg)
	if err != nil {
		b.Fatalf("encode: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(wire); err != nil {
			b.Fatalf("decode: %v", err)
		}
	}
}

func BenchmarkEncodeARecord(b *testing.B) {
	msg := &Message{
		Header:    Header{ID: 1, QR: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers:   []ResourceRecord{{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 60, Data: AData{Address: [4]byte{8, 8, 8, 8}}}},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encode(msg); err != nil {
			b.Fatalf("encode: %v", err)
		}
	}
}

func BenchmarkDecodeWithCompression(b *testing.B) {
	msg := &Message{
		Header:    Header{ID: 1, QR: true},
		Questions: []Question{{Name: "a.example.com.", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{
			{Name: "a.example.com.", Type: TypeA, Class: ClassIN, TTL: 60, Data: AData{Address: [4]byte{1, 1, 1, 1}}},
			{Name: "b.example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: CNAMEData{Name: "a.example.com."}},
		},
	}
	wire, err := Encode(msg)
	if err != nil {
		b.Fatalf("encode: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(wire); err != nil {
			b.Fatalf("decode: %v", err)
		}
	}
}

func TestEncodeDecodeRRSIG(t *testing.T) {
	t.Parallel()
	rr := ResourceRecord{
		Name:  "example.com.",
		Type:  TypeRRSIG,
		Class: ClassIN,
		TTL:   300,
		Data: RRSIGData{
			TypeCovered: TypeA,
			Algorithm:   5,
			Labels:      2,
			OriginalTTL: 3600,
			Expiration:  1700000000,
			Inception:   1699000000,
			KeyTag:      12345,
			SignerName:  "example.com.",
			Signature:   []byte{0x01, 0x02, 0x03, 0x04},
		},
	}
	msg := &Message{
		Header:    Header{ID: 1234, RD: true, QR: true, RA: true},
		Questions: []Question{{Name: "example.com.", Type: TypeRRSIG, Class: ClassIN}},
		Answers:   []ResourceRecord{rr},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.Answers) != 1 {
		t.Fatalf("answers=%d", len(decoded.Answers))
	}
	got := decoded.Answers[0].Data.(RRSIGData)
	if got.TypeCovered != TypeA || got.Algorithm != 5 || got.KeyTag != 12345 {
		t.Fatalf("rrsig mismatch: %+v", got)
	}
}

func TestEncodeDecodeDNSKEY(t *testing.T) {
	t.Parallel()
	rr := ResourceRecord{
		Name:  "example.com.",
		Type:  TypeDNSKEY,
		Class: ClassIN,
		TTL:   300,
		Data: DNSKEYData{
			Flags:     257,
			Protocol:  3,
			Algorithm: 5,
			PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}
	msg := &Message{
		Header:    Header{ID: 1234, RD: true, QR: true, RA: true},
		Questions: []Question{{Name: "example.com.", Type: TypeDNSKEY, Class: ClassIN}},
		Answers:   []ResourceRecord{rr},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	got := decoded.Answers[0].Data.(DNSKEYData)
	if got.Flags != 257 || got.Protocol != 3 || got.Algorithm != 5 {
		t.Fatalf("dnskey mismatch: %+v", got)
	}
}

func TestEncodeDecodeDS(t *testing.T) {
	t.Parallel()
	rr := ResourceRecord{
		Name:  "example.com.",
		Type:  TypeDS,
		Class: ClassIN,
		TTL:   300,
		Data: DSData{
			KeyTag:     12345,
			Algorithm:  5,
			DigestType: 1,
			Digest:     []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
	}
	msg := &Message{
		Header:    Header{ID: 1234, RD: true, QR: true, RA: true},
		Questions: []Question{{Name: "example.com.", Type: TypeDS, Class: ClassIN}},
		Answers:   []ResourceRecord{rr},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	got := decoded.Answers[0].Data.(DSData)
	if got.KeyTag != 12345 || got.Algorithm != 5 || got.DigestType != 1 {
		t.Fatalf("ds mismatch: %+v", got)
	}
}

func TestEncodeDecodeNSEC(t *testing.T) {
	t.Parallel()
	rr := ResourceRecord{
		Name:  "example.com.",
		Type:  TypeNSEC,
		Class: ClassIN,
		TTL:   300,
		Data: NSECData{
			NextDomain: "www.example.com.",
			TypeBitmap: []byte{0x00, 0x02, 0x40, 0x01},
		},
	}
	msg := &Message{
		Header:    Header{ID: 1234, RD: true, QR: true, RA: true},
		Questions: []Question{{Name: "example.com.", Type: TypeNSEC, Class: ClassIN}},
		Answers:   []ResourceRecord{rr},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	got := decoded.Answers[0].Data.(NSECData)
	if got.NextDomain != "www.example.com." {
		t.Fatalf("nsec mismatch: %+v", got)
	}
}

func TestEncodeDecodeNSEC3(t *testing.T) {
	t.Parallel()
	rr := ResourceRecord{
		Name:  "example.com.",
		Type:  TypeNSEC3,
		Class: ClassIN,
		TTL:   300,
		Data: NSEC3Data{
			HashAlgorithm: 1,
			Flags:         0,
			Iterations:    100,
			Salt:          []byte{0xAA, 0xBB},
			NextHashed:    []byte{0x01, 0x02, 0x03, 0x04},
			TypeBitmap:    []byte{0x00, 0x02, 0x40, 0x01},
		},
	}
	msg := &Message{
		Header:    Header{ID: 1234, RD: true, QR: true, RA: true},
		Questions: []Question{{Name: "example.com.", Type: TypeNSEC3, Class: ClassIN}},
		Answers:   []ResourceRecord{rr},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	got := decoded.Answers[0].Data.(NSEC3Data)
	if got.HashAlgorithm != 1 || got.Iterations != 100 {
		t.Fatalf("nsec3 mismatch: %+v", got)
	}
}

func TestEncodeDecodeOPT(t *testing.T) {
	t.Parallel()
	rr := ResourceRecord{
		Name:  ".",
		Type:  TypeOPT,
		Class: 4096,
		TTL:   0,
		Data: OPTData{
			UDPSize: 4096,
			Options: []byte{},
		},
	}
	msg := &Message{
		Header:      Header{ID: 1234, RD: true, QR: true, RA: true},
		Questions:   []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Additionals: []ResourceRecord{rr},
	}
	wire, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.Additionals) != 1 {
		t.Fatalf("additionals=%d", len(decoded.Additionals))
	}
	got := decoded.Additionals[0]
	if got.Type != TypeOPT {
		t.Fatalf("opt type mismatch: %d", got.Type)
	}
}

func TestEncodeNilMessage(t *testing.T) {
	_, err := Encode(nil)
	if err == nil {
		t.Fatalf("expected error for nil message")
	}
}

func TestSplitQNameEmptyLabel(t *testing.T) {
	_, err := splitQName("example..com.")
	if err == nil {
		t.Fatalf("expected error for empty label")
	}
}

func TestNormalizeCountMismatch(t *testing.T) {
	msg := &Message{
		Header:    Header{ID: 1, AnswerCount: 5},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers:   []ResourceRecord{{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 60, Data: AData{Address: [4]byte{1, 1, 1, 1}}}},
	}
	err := msg.NormalizeCounts()
	if err != nil {
		t.Fatalf("normalize counts: %v", err)
	}
	if msg.Header.AnswerCount != 1 {
		t.Fatalf("answer count=%d want=1", msg.Header.AnswerCount)
	}
}
