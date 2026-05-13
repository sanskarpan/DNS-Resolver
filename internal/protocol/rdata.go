package protocol

import (
	"encoding/binary"
	"fmt"
)

func parseRData(packet []byte, off int, rdLen int, rrType uint16) (RData, error) {
	if off < 0 || rdLen < 0 || off+rdLen > len(packet) {
		return nil, fmt.Errorf("invalid rdata bounds")
	}
	rdEnd := off + rdLen

	switch rrType {
	case TypeA:
		if rdLen != 4 {
			return nil, fmt.Errorf("A rdata len=%d", rdLen)
		}
		var ip [4]byte
		copy(ip[:], packet[off:rdEnd])
		return AData{Address: ip}, nil
	case TypeAAAA:
		if rdLen != 16 {
			return nil, fmt.Errorf("AAAA rdata len=%d", rdLen)
		}
		var ip [16]byte
		copy(ip[:], packet[off:rdEnd])
		return AAAAData{Address: ip}, nil
	case TypeCNAME:
		name, next, err := decodeName(packet, off)
		if err != nil {
			return nil, err
		}
		if next > rdEnd {
			return nil, fmt.Errorf("CNAME out of bounds")
		}
		return CNAMEData{Name: name}, nil
	case TypeNS:
		name, _, err := decodeName(packet, off)
		if err != nil {
			return nil, err
		}
		return NSData{Name: name}, nil
	case TypePTR:
		name, _, err := decodeName(packet, off)
		if err != nil {
			return nil, err
		}
		return PTRData{Name: name}, nil
	case TypeMX:
		if rdLen < 3 {
			return nil, fmt.Errorf("MX too short")
		}
		pref := binary.BigEndian.Uint16(packet[off : off+2])
		exchange, _, err := decodeName(packet, off+2)
		if err != nil {
			return nil, err
		}
		return MXData{Preference: pref, Exchange: exchange}, nil
	case TypeSOA:
		mname, next, err := decodeName(packet, off)
		if err != nil {
			return nil, err
		}
		rname, next2, err := decodeName(packet, next)
		if err != nil {
			return nil, err
		}
		if next2+20 > rdEnd {
			return nil, fmt.Errorf("SOA fixed fields truncated")
		}
		return SOAData{
			MName:   mname,
			RName:   rname,
			Serial:  binary.BigEndian.Uint32(packet[next2 : next2+4]),
			Refresh: binary.BigEndian.Uint32(packet[next2+4 : next2+8]),
			Retry:   binary.BigEndian.Uint32(packet[next2+8 : next2+12]),
			Expire:  binary.BigEndian.Uint32(packet[next2+12 : next2+16]),
			Minimum: binary.BigEndian.Uint32(packet[next2+16 : next2+20]),
		}, nil
	case TypeTXT:
		texts := make([]string, 0, 2)
		cur := off
		for cur < rdEnd {
			sz := int(packet[cur])
			cur++
			if cur+sz > rdEnd {
				return nil, fmt.Errorf("TXT string truncated")
			}
			texts = append(texts, string(packet[cur:cur+sz]))
			cur += sz
		}
		return TXTData{Texts: texts}, nil
	case TypeSRV:
		if rdLen < 7 {
			return nil, fmt.Errorf("SRV too short")
		}
		prio := binary.BigEndian.Uint16(packet[off : off+2])
		weight := binary.BigEndian.Uint16(packet[off+2 : off+4])
		port := binary.BigEndian.Uint16(packet[off+4 : off+6])
		target, _, err := decodeName(packet, off+6)
		if err != nil {
			return nil, err
		}
		return SRVData{Priority: prio, Weight: weight, Port: port, Target: target}, nil
	case TypeCAA:
		if rdLen < 2 {
			return nil, fmt.Errorf("CAA too short")
		}
		flags := packet[off]
		tagLen := int(packet[off+1])
		if off+2+tagLen > rdEnd {
			return nil, fmt.Errorf("CAA tag truncated")
		}
		tag := string(packet[off+2 : off+2+tagLen])
		val := string(packet[off+2+tagLen : rdEnd])
		return CAAData{Flags: flags, Tag: tag, Value: val}, nil
	case TypeRRSIG:
		if rdLen < 18 {
			return nil, fmt.Errorf("RRSIG too short")
		}
		typeCovered := binary.BigEndian.Uint16(packet[off : off+2])
		algo := packet[off+2]
		labels := packet[off+3]
		origTTL := binary.BigEndian.Uint32(packet[off+4 : off+8])
		exp := binary.BigEndian.Uint32(packet[off+8 : off+12])
		inc := binary.BigEndian.Uint32(packet[off+12 : off+16])
		keyTag := binary.BigEndian.Uint16(packet[off+16 : off+18])
		signer, next, err := decodeName(packet, off+18)
		if err != nil {
			return nil, err
		}
		if next > rdEnd {
			return nil, fmt.Errorf("RRSIG signature truncated")
		}
		sig := append([]byte(nil), packet[next:rdEnd]...)
		return RRSIGData{
			TypeCovered: typeCovered,
			Algorithm:   algo,
			Labels:      labels,
			OriginalTTL: origTTL,
			Expiration:  exp,
			Inception:   inc,
			KeyTag:      keyTag,
			SignerName:  signer,
			Signature:   sig,
		}, nil
	case TypeDNSKEY:
		if rdLen < 4 {
			return nil, fmt.Errorf("DNSKEY too short")
		}
		return DNSKEYData{
			Flags:     binary.BigEndian.Uint16(packet[off : off+2]),
			Protocol:  packet[off+2],
			Algorithm: packet[off+3],
			PublicKey: append([]byte(nil), packet[off+4:rdEnd]...),
		}, nil
	case TypeDS:
		if rdLen < 4 {
			return nil, fmt.Errorf("DS too short")
		}
		return DSData{
			KeyTag:     binary.BigEndian.Uint16(packet[off : off+2]),
			Algorithm:  packet[off+2],
			DigestType: packet[off+3],
			Digest:     append([]byte(nil), packet[off+4:rdEnd]...),
		}, nil
	case TypeNSEC:
		nextDomain, next, err := decodeName(packet, off)
		if err != nil {
			return nil, err
		}
		if next > rdEnd {
			return nil, fmt.Errorf("NSEC type bitmap truncated")
		}
		return NSECData{NextDomain: nextDomain, TypeBitmap: append([]byte(nil), packet[next:rdEnd]...)}, nil
	case TypeNSEC3:
		if rdLen < 5 {
			return nil, fmt.Errorf("NSEC3 too short")
		}
		cur := off
		hashAlgo := packet[cur]
		cur++
		flags := packet[cur]
		cur++
		iterations := binary.BigEndian.Uint16(packet[cur : cur+2])
		cur += 2
		saltLen := int(packet[cur])
		cur++
		if cur+saltLen > rdEnd {
			return nil, fmt.Errorf("NSEC3 salt truncated")
		}
		salt := append([]byte(nil), packet[cur:cur+saltLen]...)
		cur += saltLen
		if cur >= rdEnd {
			return nil, fmt.Errorf("NSEC3 hash length missing")
		}
		hashLen := int(packet[cur])
		cur++
		if cur+hashLen > rdEnd {
			return nil, fmt.Errorf("NSEC3 hash truncated")
		}
		nextHash := append([]byte(nil), packet[cur:cur+hashLen]...)
		cur += hashLen
		return NSEC3Data{
			HashAlgorithm: hashAlgo,
			Flags:         flags,
			Iterations:    iterations,
			Salt:          salt,
			NextHashed:    nextHash,
			TypeBitmap:    append([]byte(nil), packet[cur:rdEnd]...),
		}, nil
	default:
		return UnknownData{Type: rrType, Data: append([]byte(nil), packet[off:rdEnd]...)}, nil
	}
}

func encodeRData(w *packetWriter, rrType uint16, data RData, raw []byte, compression map[string]int) error {
	if rrType == TypeOPT {
		if d, ok := data.(OPTData); ok {
			w.WriteBytes(d.Options)
			return nil
		}
	}

	if data == nil {
		w.WriteBytes(raw)
		return nil
	}

	switch d := data.(type) {
	case AData:
		w.WriteBytes(d.Address[:])
	case AAAAData:
		w.WriteBytes(d.Address[:])
	case CNAMEData:
		return writeName(w, d.Name, compression)
	case NSData:
		return writeName(w, d.Name, compression)
	case PTRData:
		return writeName(w, d.Name, compression)
	case MXData:
		w.WriteUint16(d.Preference)
		return writeName(w, d.Exchange, compression)
	case SOAData:
		if err := writeName(w, d.MName, compression); err != nil {
			return err
		}
		if err := writeName(w, d.RName, compression); err != nil {
			return err
		}
		w.WriteUint32(d.Serial)
		w.WriteUint32(d.Refresh)
		w.WriteUint32(d.Retry)
		w.WriteUint32(d.Expire)
		w.WriteUint32(d.Minimum)
	case TXTData:
		for _, s := range d.Texts {
			if len(s) > 255 {
				return fmt.Errorf("TXT chunk too long: %d", len(s))
			}
			w.WriteByte(byte(len(s)))
			w.WriteBytes([]byte(s))
		}
	case SRVData:
		w.WriteUint16(d.Priority)
		w.WriteUint16(d.Weight)
		w.WriteUint16(d.Port)
		return writeName(w, d.Target, compression)
	case CAAData:
		if len(d.Tag) > 255 {
			return fmt.Errorf("CAA tag too long")
		}
		w.WriteByte(d.Flags)
		w.WriteByte(byte(len(d.Tag)))
		w.WriteBytes([]byte(d.Tag))
		w.WriteBytes([]byte(d.Value))
	case RRSIGData:
		w.WriteUint16(d.TypeCovered)
		w.WriteByte(d.Algorithm)
		w.WriteByte(d.Labels)
		w.WriteUint32(d.OriginalTTL)
		w.WriteUint32(d.Expiration)
		w.WriteUint32(d.Inception)
		w.WriteUint16(d.KeyTag)
		if err := writeName(w, d.SignerName, compression); err != nil {
			return err
		}
		w.WriteBytes(d.Signature)
	case DNSKEYData:
		w.WriteUint16(d.Flags)
		w.WriteByte(d.Protocol)
		w.WriteByte(d.Algorithm)
		w.WriteBytes(d.PublicKey)
	case DSData:
		w.WriteUint16(d.KeyTag)
		w.WriteByte(d.Algorithm)
		w.WriteByte(d.DigestType)
		w.WriteBytes(d.Digest)
	case NSECData:
		if err := writeName(w, d.NextDomain, compression); err != nil {
			return err
		}
		w.WriteBytes(d.TypeBitmap)
	case NSEC3Data:
		w.WriteByte(d.HashAlgorithm)
		w.WriteByte(d.Flags)
		w.WriteUint16(d.Iterations)
		if len(d.Salt) > 255 || len(d.NextHashed) > 255 {
			return fmt.Errorf("NSEC3 field too long")
		}
		w.WriteByte(byte(len(d.Salt)))
		w.WriteBytes(d.Salt)
		w.WriteByte(byte(len(d.NextHashed)))
		w.WriteBytes(d.NextHashed)
		w.WriteBytes(d.TypeBitmap)
	case OPTData:
		w.WriteBytes(d.Options)
	case UnknownData:
		w.WriteBytes(d.Data)
	default:
		w.WriteBytes(raw)
	}
	return nil
}
