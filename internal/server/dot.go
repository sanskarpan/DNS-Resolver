package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type DoTServer struct {
	tcp *TCPServer
}

func NewDoTServer(addr string, handler *Handler, maxConn int, certPath, keyPath string, autoGenerate bool) (*DoTServer, error) {
	if autoGenerate {
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			if err := generateSelfSignedCert(certPath, keyPath); err != nil {
				return nil, err
			}
		}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	tcpSrv := NewTCPServer(addr, handler, maxConn)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tcpSrv.listener = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	return &DoTServer{tcp: tcpSrv}, nil
}

func (s *DoTServer) Start(ctx context.Context) error {
	if s.tcp.listener == nil {
		return nil
	}
	s.tcp.running.Store(true)
	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()
	go s.tcp.acceptLoop(ctx)
	return nil
}

func (s *DoTServer) Shutdown(ctx context.Context) error {
	if s == nil || s.tcp == nil {
		return nil
	}
	return s.tcp.Shutdown(ctx)
}

func generateSelfSignedCert(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil && filepath.Dir(certPath) != "." {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil && filepath.Dir(keyPath) != "." {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "dns-resolver.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "dns-resolver.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}
	return nil
}
