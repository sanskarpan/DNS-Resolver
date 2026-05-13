package resolver

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"dnsresolver/internal/protocol"
	"dnsresolver/internal/security"
)

type queryResult struct {
	server       string
	serverName   string
	requestWire  []byte
	responseWire []byte
	message      *protocol.Message
	latency      time.Duration
	err          error
}

func (r *Resolver) queryFastest(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string, cfg Config) (*protocol.Message, []ResolutionEvent, error) {
	if len(servers) == 0 {
		return nil, nil, fmt.Errorf("no upstream servers")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resultCh := make(chan queryResult, len(servers))
	var wg sync.WaitGroup
	started := 0

	for _, server := range servers {
		cb := r.getBreaker(server, cfg)
		if !cb.Allow() {
			err := fmt.Errorf("circuit open")
			r.observeUpstreamResult(server, "", 0, err)
			resultCh <- queryResult{server: server, err: err}
			continue
		}
		started++
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			res := r.queryWithRetries(ctx, server, qname, qtype, cfg)
			if res.err != nil {
				cb.OnFailure()
			} else {
				cb.OnSuccess()
			}
			r.observeUpstreamResult(server, res.serverName, res.latency, res.err)
			resultCh <- res
		}(server)
	}

	if started == 0 {
		return nil, nil, fmt.Errorf("all circuits open")
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	events := make([]ResolutionEvent, 0, len(servers))
	var firstErr error
	for res := range resultCh {
		ev := ResolutionEvent{
			QueryID:     queryID,
			Timestamp:   time.Now().UTC(),
			Step:        step,
			StepType:    stepTypeFor(step),
			Server:      res.server,
			ServerName:  res.serverName,
			Query:       normalizeFQDN(qname),
			QueryType:   protocol.TypeToString(qtype),
			Latency:     res.latency.Milliseconds(),
			Success:     res.err == nil,
			RawRequest:  res.requestWire,
			RawResponse: res.responseWire,
			ParsedMsg:   res.message,
		}
		if res.err != nil {
			ev.ErrorMsg = res.err.Error()
		}
		events = append(events, ev)
		if res.err == nil && res.message != nil {
			cancel()
			return res.message, events, nil
		}
		if firstErr == nil {
			firstErr = res.err
		}
	}

	if firstErr == nil {
		firstErr = errors.New("all upstream queries failed")
	}
	return nil, events, firstErr
}

func stepTypeFor(step int) string {
	switch step {
	case 1:
		return "root_query"
	case 2:
		return "tld_query"
	default:
		return "auth_query"
	}
}

func (r *Resolver) queryWithRetries(ctx context.Context, server string, qname string, qtype uint16, cfg Config) queryResult {
	var last queryResult
	for attempt := 0; attempt < cfg.Retries; attempt++ {
		res := r.queryOnce(ctx, server, qname, qtype, cfg)
		if res.err == nil {
			return res
		}
		last = res
		jitter, _ := randomJitter(50 * time.Millisecond)
		backoff := time.Duration(1<<attempt)*100*time.Millisecond + jitter
		select {
		case <-ctx.Done():
			last.err = ctx.Err()
			return last
		case <-time.After(backoff):
		}
	}
	return last
}

func randomJitter(max time.Duration) (time.Duration, error) {
	if max <= 0 {
		return 0, nil
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint16(b[:])
	return time.Duration(v%uint16(max.Milliseconds()+1)) * time.Millisecond, nil
}

func (r *Resolver) queryOnce(ctx context.Context, server string, qname string, qtype uint16, cfg Config) queryResult {
	start := time.Now()
	res := queryResult{server: server, serverName: server}
	id, err := r.qid.Acquire()
	if err != nil {
		res.err = err
		return res
	}
	defer r.qid.Release(id)

	sentName := normalizeFQDN(qname)
	if cfg.CaseRandomization {
		randomized, err := r.cases.RandomizeQName(sentName)
		if err != nil {
			res.err = err
			return res
		}
		sentName = randomized
	}

	msg := buildUpstreamQuery(id, sentName, qtype, cfg)
	wire, err := protocol.Encode(msg)
	if err != nil {
		res.err = fmt.Errorf("encode request: %w", err)
		return res
	}
	res.requestWire = wire

	conn, err := r.ports.ListenUDP()
	if err != nil {
		res.err = err
		return res
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(cfg.UpstreamTimeout)); err != nil {
		res.err = err
		return res
	}

	ip := net.ParseIP(server)
	if ip == nil {
		res.err = fmt.Errorf("invalid server ip: %s", server)
		return res
	}
	remote := &net.UDPAddr{IP: ip, Port: r.upstreamPort}
	if _, err := conn.WriteToUDP(wire, remote); err != nil {
		res.err = fmt.Errorf("send query: %w", err)
		return res
	}

	buf := make([]byte, cfg.MaxUDPSize)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		res.err = fmt.Errorf("read response: %w", err)
		return res
	}
	if !addr.IP.Equal(ip) || addr.Port != r.upstreamPort {
		r.incSecurityCounter("poisoning_source_mismatch")
		res.err = fmt.Errorf("response source mismatch from %s:%d", addr.IP, addr.Port)
		return res
	}
	respWire := append([]byte(nil), buf[:n]...)
	res.responseWire = respWire

	decoded, err := protocol.Decode(respWire)
	if err != nil {
		res.err = fmt.Errorf("decode response: %w", err)
		return res
	}
	if decoded.Header.ID != id {
		r.incSecurityCounter("poisoning_id_mismatch")
		res.err = fmt.Errorf("query id mismatch: want=%d got=%d", id, decoded.Header.ID)
		return res
	}
	if reason, err := validateResponseQuestion(sentName, qtype, cfg.CaseRandomization, decoded, r.cases); err != nil {
		r.incSecurityCounter(reason)
		res.err = err
		return res
	}
	if decoded.Header.TC {
		return r.queryTCP(ctx, server, wire, id, sentName, qtype, cfg, start)
	}
	res.message = decoded
	res.latency = time.Since(start)
	return res
}

func buildUpstreamQuery(id uint16, qname string, qtype uint16, cfg Config) *protocol.Message {
	msg := &protocol.Message{
		Header:    protocol.Header{ID: id, RD: true},
		Questions: []protocol.Question{{Name: qname, Type: qtype, Class: protocol.ClassIN}},
	}
	if cfg.EDNSEnabled {
		msg.Additionals = []protocol.ResourceRecord{{
			Name:  ".",
			Type:  protocol.TypeOPT,
			Class: uint16(cfg.MaxUDPSize),
			TTL:   0,
			Data:  protocol.OPTData{UDPSize: uint16(cfg.MaxUDPSize)},
		}}
	}
	return msg
}

func (r *Resolver) queryTCP(ctx context.Context, server string, wire []byte, id uint16, sentName string, qtype uint16, cfg Config, started time.Time) queryResult {
	res := queryResult{
		server:      server,
		serverName:  server,
		requestWire: append([]byte(nil), wire...),
	}

	ip := net.ParseIP(server)
	if ip == nil {
		res.err = fmt.Errorf("invalid server ip: %s", server)
		return res
	}

	dialer := &net.Dialer{Timeout: cfg.UpstreamTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", r.upstreamPort)))
	if err != nil {
		res.err = fmt.Errorf("tcp fallback dial: %w", err)
		return res
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(cfg.UpstreamTimeout)); err != nil {
		res.err = err
		return res
	}

	reader := bufio.NewReader(conn)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		res.err = fmt.Errorf("tcp fallback write len: %w", err)
		return res
	}
	if _, err := conn.Write(wire); err != nil {
		res.err = fmt.Errorf("tcp fallback write payload: %w", err)
		return res
	}
	if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
		res.err = fmt.Errorf("tcp fallback read len: %w", err)
		return res
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size <= 0 || size > protocol.MaxDNSPacketLen {
		res.err = fmt.Errorf("tcp fallback invalid response size: %d", size)
		return res
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		res.err = fmt.Errorf("tcp fallback read payload: %w", err)
		return res
	}
	res.responseWire = append([]byte(nil), payload...)

	decoded, err := protocol.Decode(payload)
	if err != nil {
		res.err = fmt.Errorf("tcp fallback decode response: %w", err)
		return res
	}
	if decoded.Header.ID != id {
		r.incSecurityCounter("poisoning_id_mismatch")
		res.err = fmt.Errorf("query id mismatch: want=%d got=%d", id, decoded.Header.ID)
		return res
	}
	if reason, err := validateResponseQuestion(sentName, qtype, cfg.CaseRandomization, decoded, r.cases); err != nil {
		r.incSecurityCounter(reason)
		res.err = err
		return res
	}

	res.message = decoded
	res.latency = time.Since(started)
	return res
}

func validateResponseQuestion(sentName string, qtype uint16, caseRandomization bool, decoded *protocol.Message, cases *security.CaseRandomizer) (string, error) {
	if decoded == nil || len(decoded.Questions) == 0 {
		return "poisoning_question_missing", fmt.Errorf("response question missing")
	}
	q := decoded.Questions[0]
	if normalizeFQDN(q.Name) != normalizeFQDN(sentName) {
		return "poisoning_name_mismatch", fmt.Errorf("response qname mismatch: sent=%s got=%s", sentName, q.Name)
	}
	if q.Type != qtype || q.Class != protocol.ClassIN {
		return "poisoning_question_mismatch", fmt.Errorf("response question mismatch: type=%d class=%d", q.Type, q.Class)
	}
	if caseRandomization && cases != nil && !cases.Matches(sentName, q.Name) {
		return "poisoning_case_mismatch", fmt.Errorf("0x20 case mismatch")
	}
	return "", nil
}
