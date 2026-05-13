package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMainServerStartsAndShutsDown(t *testing.T) {
	dnsPort := findFreeDualStackPort(t)
	httpPort := findFreeTCPPort(t)
	workDir := t.TempDir()
	cachePath := filepath.Join(workDir, "state", "cache.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelperProcess", "--")
	cmd.Env = append(os.Environ(),
		"GO_WANT_MAIN_HELPER=1",
		fmt.Sprintf("DNS_PORT=%d", dnsPort),
		fmt.Sprintf("HTTP_PORT=%d", httpPort),
		"CACHE_PERSIST_PATH="+cachePath,
		"BLOCKLIST_PATH="+filepath.Join(workDir, "blocklist.txt"),
		"TLS_ENABLED=false",
		"PROMETHEUS_ENABLED=false",
		"PPROF_ENABLED=false",
		"OTEL_ENABLED=false",
		"QNAME_MINIMIZATION=false",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	defer func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	readyURL := fmt.Sprintf("http://127.0.0.1:%d/api/v1/health/ready", httpPort)
	if err := waitForHTTPStatus(readyURL, http.StatusOK, 10*time.Second); err != nil {
		t.Fatalf("wait for readiness: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/health/live", httpPort))
	if err != nil {
		t.Fatalf("live probe: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("live probe status=%d want=%d", resp.StatusCode, http.StatusOK)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal helper process: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("helper process exited with error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for helper process shutdown")
	}

	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache snapshot to be persisted at shutdown: %v", err)
	}
}

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_MAIN_HELPER") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"dnsresolver"}
	main()
	os.Exit(0)
}

func findFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func findFreeDualStackPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 32; i++ {
		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("find free dual-stack port tcp listen: %v", err)
		}
		port := tcpLn.Addr().(*net.TCPAddr).Port
		_ = tcpLn.Close()

		udpLn, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = udpLn.Close()
			return port
		}
	}
	t.Fatal("unable to find free shared tcp/udp port")
	return 0
}

func waitForHTTPStatus(url string, want int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{Timeout: 500 * time.Millisecond}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
