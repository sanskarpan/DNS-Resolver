package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

type udpPacket struct {
	data []byte
	addr *net.UDPAddr
	buf  []byte
}

type UDPServer struct {
	addr    string
	handler *Handler
	workers int

	conn     *net.UDPConn
	queue    chan udpPacket
	readWG   sync.WaitGroup
	workWG   sync.WaitGroup
	running  atomic.Bool
	shutdown chan struct{}
	bufPool  sync.Pool
}

func NewUDPServer(addr string, handler *Handler, workers int) *UDPServer {
	if workers <= 0 {
		workers = 1000
	}
	return &UDPServer{
		addr:     addr,
		handler:  handler,
		workers:  workers,
		shutdown: make(chan struct{}),
		bufPool: sync.Pool{
			New: func() any {
				return make([]byte, 65535)
			},
		},
	}
}

func (s *UDPServer) Start(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.conn = conn
	s.queue = make(chan udpPacket, s.workers*2)
	s.running.Store(true)

	for i := 0; i < s.workers; i++ {
		s.workWG.Add(1)
		go s.worker(ctx)
	}

	s.readWG.Add(1)
	go s.readLoop(ctx)

	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()
	return nil
}

func (s *UDPServer) readLoop(ctx context.Context) {
	defer s.readWG.Done()
	for {
		buf := s.bufPool.Get().([]byte)
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.bufPool.Put(buf)
			if !s.running.Load() {
				return
			}
			continue
		}
		pkt := udpPacket{data: buf[:n], addr: addr, buf: buf}
		select {
		case s.queue <- pkt:
		case <-ctx.Done():
			s.bufPool.Put(buf)
			return
		default:
			// drop if queue is full to avoid unbounded goroutines
			s.bufPool.Put(buf)
		}
	}
}

func (s *UDPServer) worker(ctx context.Context) {
	defer s.workWG.Done()
	for {
		select {
		case pkt, ok := <-s.queue:
			if !ok {
				return
			}
			resp, drop, err := s.handler.HandlePacket(ctx, pkt.data, pkt.addr, "udp")
			if pkt.buf != nil {
				s.bufPool.Put(pkt.buf)
			}
			if err != nil || drop || len(resp) == 0 {
				continue
			}
			_, _ = s.conn.WriteToUDP(resp, pkt.addr)
		case <-ctx.Done():
			return
		}
	}
}

func (s *UDPServer) Shutdown(ctx context.Context) error {
	if !s.running.Swap(false) {
		return nil
	}
	close(s.shutdown)
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.readWG.Wait()
	if s.queue != nil {
		close(s.queue)
	}
	done := make(chan struct{})
	go func() {
		s.workWG.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return errors.New("udp shutdown timeout")
	case <-done:
		return nil
	}
}

func (s *UDPServer) LocalAddr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}
