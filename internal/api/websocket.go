package api

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type wsConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func (c *wsConn) Close() error {
	return c.conn.Close()
}

func (c *wsConn) WriteJSON(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.writeFrame(0x1, payload)
}

func (c *wsConn) WritePing() error {
	return c.writeFrame(0x9, nil)
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	header := []byte{0x80 | opcode}
	n := len(payload)
	switch {
	case n <= 125:
		header = append(header, byte(n))
	case n <= 65535:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n),
		)
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func acceptWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if r.Method != http.MethodGet {
		return nil, fmt.Errorf("method not allowed")
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("not a websocket upgrade")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, fmt.Errorf("unsupported websocket version")
	}
	if err := validateWebSocketOrigin(r); err != nil {
		return nil, err
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, fmt.Errorf("missing websocket key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijacker not supported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := websocketAccept(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn}, nil
}

func validateWebSocketOrigin(r *http.Request) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid websocket origin")
	}
	if !strings.EqualFold(u.Host, r.Host) {
		return fmt.Errorf("forbidden websocket origin")
	}
	return nil
}

func drainWebSocketControl(ctx context.Context, c *wsConn) {
	defer c.Close()
	const maxFramePayload = 125
	var header [2]byte
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(65 * time.Second))
		if _, err := io.ReadFull(c.conn, header[:]); err != nil {
			return
		}
		fin := header[0]&0x80 != 0
		opcode := header[0] & 0x0f
		masked := header[1]&0x80 != 0
		payloadLen := int(header[1] & 0x7f)
		if !fin {
			return
		}
		if payloadLen == 126 || payloadLen == 127 || payloadLen > maxFramePayload {
			return
		}
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.conn, maskKey[:]); err != nil {
				return
			}
		}
		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(c.conn, payload); err != nil {
				return
			}
			if masked {
				for i := range payload {
					payload[i] ^= maskKey[i%4]
				}
			}
		}
		switch opcode {
		case 0x8:
			_ = c.writeFrame(0x8, payload)
			return
		case 0x9:
			if err := c.writeFrame(0xA, payload); err != nil {
				return
			}
		case 0xA:
			continue
		default:
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func websocketAccept(key string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (a *API) wsTrace(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.deps.Resolver == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "trace stream unavailable"})
			return
		}
		c, err := acceptWebSocket(w, r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		defer c.Close()
		go drainWebSocketControl(ctx, c)
		sub := a.deps.Resolver.Subscribe(256)
		defer a.deps.Resolver.Unsubscribe(sub)
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		_ = c.conn.SetReadDeadline(time.Now().Add(24 * time.Hour))
		for {
			select {
			case ev := <-sub:
				if err := c.WriteJSON(ev); err != nil {
					return
				}
			case <-ping.C:
				if err := c.WritePing(); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
}

func (a *API) wsMetrics(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.deps.Metrics == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "metrics stream unavailable"})
			return
		}
		c, err := acceptWebSocket(w, r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		defer c.Close()
		go drainWebSocketControl(ctx, c)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-t.C:
				if err := c.WriteJSON(a.deps.Metrics.Snapshot()); err != nil {
					return
				}
			case <-ping.C:
				if err := c.WritePing(); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
}

func (a *API) wsQueries(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.deps.DNSHandler == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "query stream unavailable"})
			return
		}
		c, err := acceptWebSocket(w, r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		defer c.Close()
		go drainWebSocketControl(ctx, c)
		sub := a.deps.DNSHandler.SubscribeQueries(256)
		defer a.deps.DNSHandler.UnsubscribeQueries(sub)
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		for {
			select {
			case ev := <-sub:
				if err := c.WriteJSON(ev); err != nil {
					return
				}
			case <-ping.C:
				if err := c.WritePing(); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
}
