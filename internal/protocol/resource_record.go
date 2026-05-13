package protocol

type ResourceRecord struct {
	Name     string `json:"name"`
	Type     uint16 `json:"type"`
	Class    uint16 `json:"class"`
	TTL      uint32 `json:"ttl"`
	Data     RData  `json:"data,omitempty"`
	RawRData []byte `json:"raw_rdata,omitempty"`
}

type RData interface {
	recordType() uint16
}

type AData struct {
	Address [4]byte `json:"address"`
}

func (AData) recordType() uint16 { return TypeA }

type AAAAData struct {
	Address [16]byte `json:"address"`
}

func (AAAAData) recordType() uint16 { return TypeAAAA }

type CNAMEData struct {
	Name string `json:"name"`
}

func (CNAMEData) recordType() uint16 { return TypeCNAME }

type NSData struct {
	Name string `json:"name"`
}

func (NSData) recordType() uint16 { return TypeNS }

type PTRData struct {
	Name string `json:"name"`
}

func (PTRData) recordType() uint16 { return TypePTR }

type MXData struct {
	Preference uint16 `json:"preference"`
	Exchange   string `json:"exchange"`
}

func (MXData) recordType() uint16 { return TypeMX }

type SOAData struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

func (SOAData) recordType() uint16 { return TypeSOA }

type TXTData struct {
	Texts []string `json:"texts"`
}

func (TXTData) recordType() uint16 { return TypeTXT }

type SRVData struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

func (SRVData) recordType() uint16 { return TypeSRV }

type CAAData struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

func (CAAData) recordType() uint16 { return TypeCAA }

type RRSIGData struct {
	TypeCovered uint16 `json:"type_covered"`
	Algorithm   uint8  `json:"algorithm"`
	Labels      uint8  `json:"labels"`
	OriginalTTL uint32 `json:"original_ttl"`
	Expiration  uint32 `json:"expiration"`
	Inception   uint32 `json:"inception"`
	KeyTag      uint16 `json:"key_tag"`
	SignerName  string `json:"signer_name"`
	Signature   []byte `json:"signature"`
}

func (RRSIGData) recordType() uint16 { return TypeRRSIG }

type DNSKEYData struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey []byte `json:"public_key"`
}

func (DNSKEYData) recordType() uint16 { return TypeDNSKEY }

type DSData struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     []byte `json:"digest"`
}

func (DSData) recordType() uint16 { return TypeDS }

type NSECData struct {
	NextDomain string `json:"next_domain"`
	TypeBitmap []byte `json:"type_bitmap"`
}

func (NSECData) recordType() uint16 { return TypeNSEC }

type NSEC3Data struct {
	HashAlgorithm uint8  `json:"hash_algorithm"`
	Flags         uint8  `json:"flags"`
	Iterations    uint16 `json:"iterations"`
	Salt          []byte `json:"salt"`
	NextHashed    []byte `json:"next_hashed"`
	TypeBitmap    []byte `json:"type_bitmap"`
}

func (NSEC3Data) recordType() uint16 { return TypeNSEC3 }

type OPTData struct {
	UDPSize  uint16 `json:"udp_size"`
	ExtRCode uint8  `json:"ext_rcode"`
	Version  uint8  `json:"version"`
	Flags    uint16 `json:"flags"`
	Options  []byte `json:"options"`
}

func (OPTData) recordType() uint16 { return TypeOPT }

// UnknownData preserves unsupported RDATA as-is.
type UnknownData struct {
	Type uint16 `json:"type"`
	Data []byte `json:"data"`
}

func (u UnknownData) recordType() uint16 { return u.Type }
