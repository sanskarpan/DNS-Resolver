package protocol

import "fmt"

const (
	MaxDNSPacketLen = 65535
	HeaderSize      = 12
	MaxLabelLength  = 63
	MaxLabels       = 127
	MaxNameLength   = 255
	MaxUDPPacketLen = 4096
)

const (
	ClassIN  uint16 = 1
	ClassCH  uint16 = 3
	ClassHS  uint16 = 4
	ClassANY uint16 = 255
)

const (
	TypeA      uint16 = 1
	TypeNS     uint16 = 2
	TypeCNAME  uint16 = 5
	TypeSOA    uint16 = 6
	TypePTR    uint16 = 12
	TypeMX     uint16 = 15
	TypeTXT    uint16 = 16
	TypeAAAA   uint16 = 28
	TypeSRV    uint16 = 33
	TypeOPT    uint16 = 41
	TypeDS     uint16 = 43
	TypeRRSIG  uint16 = 46
	TypeNSEC   uint16 = 47
	TypeDNSKEY uint16 = 48
	TypeNSEC3  uint16 = 50
	TypeCAA    uint16 = 257
	TypeANY    uint16 = 255
)

const (
	OpcodeQuery  = 0
	OpcodeIQuery = 1
	OpcodeStatus = 2
)

const (
	RCodeNoError        = 0
	RCodeFormatError    = 1
	RCodeServerFailure  = 2
	RCodeNameError      = 3
	RCodeNotImplemented = 4
	RCodeRefused        = 5
)

func TypeToString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeDS:
		return "DS"
	case TypeRRSIG:
		return "RRSIG"
	case TypeNSEC:
		return "NSEC"
	case TypeDNSKEY:
		return "DNSKEY"
	case TypeNSEC3:
		return "NSEC3"
	case TypeCAA:
		return "CAA"
	case TypeANY:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func RCodeToString(code uint8) string {
	switch code {
	case RCodeNoError:
		return "NOERROR"
	case RCodeFormatError:
		return "FORMERR"
	case RCodeServerFailure:
		return "SERVFAIL"
	case RCodeNameError:
		return "NXDOMAIN"
	case RCodeNotImplemented:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}
