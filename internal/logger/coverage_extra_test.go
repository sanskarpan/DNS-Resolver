package logger

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestNewWritesJSONAndTextToStdout(t *testing.T) {
	cases := []struct {
		name   string
		format string
		want   string
	}{
		{name: "json", format: "json", want: `"msg":"hello"`},
		{name: "text", format: "text", want: "msg=hello"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			originalStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("pipe: %v", err)
			}
			os.Stdout = w
			defer func() { os.Stdout = originalStdout }()

			l := New("debug", tc.format)
			l.Info("hello")
			_ = w.Close()

			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				t.Fatalf("read stdout: %v", err)
			}
			_ = r.Close()
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("expected %q in output: %s", tc.want, buf.String())
			}
		})
	}
}
