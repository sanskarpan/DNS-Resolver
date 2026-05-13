package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dnsresolver/internal/protocol"
)

type TCPServer struct {
	addr     string
	handler  *Handler
	maxConn  int
	idleTO   time.Duration
	listener net.Listener
	sem      chan struct{}
	wg       sync.WaitGroup
	running  atomic.Bool
}

func NewTCPServer(addr string, handler *Handler, maxConn int) *TCPServer {
	if maxConn <= 0 {
		maxConn = 500
	}
	return &TCPServer{addr: addr, handler: handler, maxConn: maxConn, idleTO: 30 * time.Second, sem: make(chan struct{}, maxConn)}
}

func (s *TCPServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.running.Store(true)
	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()
	go s.acceptLoop(ctx)
	return nil
}

func (s *TCPServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !s.running.Load() {
				return
			}
			continue
		}
		select {
		case s.sem <- struct{}{}:
			s.wg.Add(1)
			go s.serveConn(ctx, conn)
		default:
			go s.refuseConn(conn)
		}
	}
}

func (s *TCPServer) refuseConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	sz := int(binary.BigEndian.Uint16(lenBuf[:]))
	if sz <= 0 || sz > 65535 {
		return
	}
	payload := make([]byte, sz)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}
	resp, err := refusedResponse(payload)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return
	}
	_, _ = conn.Write(resp)
}

func refusedResponse(queryWire []byte) ([]byte, error) {
	msg, err := protocol.Decode(queryWire)
	if err != nil || msg == nil {
		id := uint16(0)
		if len(queryWire) >= 2 {
			id = uint16(queryWire[0])<<8 | uint16(queryWire[1])
		}
		out := &protocol.Message{Header: protocol.Header{ID: id, QR: true, RA: true, RCode: protocol.RCodeRefused}}
		wire, encErr := protocol.Encode(out)
		if encErr != nil {
			return nil, fmt.Errorf("encode fallback refused response: %w", encErr)
		}
		return wire, nil
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:     msg.Header.ID,
			QR:     true,
			RA:     true,
			RD:     msg.Header.RD,
			Opcode: msg.Header.Opcode,
			RCode:  protocol.RCodeRefused,
		},
		Questions: msg.Questions,
	}
	wire, err := protocol.Encode(resp)
	if err != nil {
		return nil, fmt.Errorf("encode refused response: %w", err)
	}
	return wire, nil
}

func (s *TCPServer) serveConn(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.sem }()
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		_ = conn.SetDeadline(time.Now().Add(s.idleTO))
		var lenBuf [2]byte
		if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
			return
		}
		sz := int(binary.BigEndian.Uint16(lenBuf[:]))
		if sz <= 0 {
			return
		}
		payload := make([]byte, sz)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return
		}
		resp, drop, err := s.handler.HandlePacket(ctx, payload, conn.RemoteAddr(), "tcp")
		if err != nil || drop || len(resp) == 0 {
			return
		}
		if len(resp) > 65535 {
			return
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

func (s *TCPServer) Shutdown(ctx context.Context) error {
	if !s.running.Swap(false) {
		return nil
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return errors.New("tcp shutdown timeout")
	case <-done:
		return nil
	}
}

func (s *TCPServer) LocalAddr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}
