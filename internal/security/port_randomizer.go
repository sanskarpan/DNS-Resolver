package security

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	minEphemeralPort = 1024
	maxEphemeralPort = 65535
)

type PortRandomizer struct{}

func NewPortRandomizer() *PortRandomizer {
	return &PortRandomizer{}
}

func (p *PortRandomizer) RandomPort() (int, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("read random: %w", err)
	}
	span := maxEphemeralPort - minEphemeralPort + 1
	port := minEphemeralPort + int(binary.BigEndian.Uint16(b[:]))%span
	return port, nil
}

func (p *PortRandomizer) ListenUDP() (*net.UDPConn, error) {
	for i := 0; i < 10; i++ {
		port, err := p.RandomPort()
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("unable to allocate random source port")
}
