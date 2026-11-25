package dynamicproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/info/logger"
)

// minXNetMinor is the first golang.org/x/net v0.x release that carries the fixes
// for the HTTP/2 server issues GO-2026-6617, GO-2026-6612, GO-2026-6611 and
// GO-2026-6603 (v0.60.0) plus GO-2026-6860 (v0.62.0).
const minXNetMinor = 62

// The x/net HTTP/2 server is what handles h2 on the public TLS listener as soon as
// any of the H2 tuning options is set (see configureHTTP2), so the module must not
// be downgraded below the patched release.
func TestXNetHTTP2ServerIsPatchedVersion(t *testing.T) {
	gomod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\s*golang\.org/x/net v(\d+)\.(\d+)\.(\d+)`).FindSubmatch(gomod)
	if m == nil {
		t.Fatal("golang.org/x/net requirement not found in go.mod")
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	if major == 0 && minor < minXNetMinor {
		t.Fatalf("golang.org/x/net v%s.%s.%s has known HTTP/2 server vulnerabilities, need at least v0.%d.0", m[1], m[2], m[3], minXNetMinor)
	}
}

// With nothing overridden the stdlib's bundled HTTP/2 must stay in place, and with
// HTTP/2 disabled no h2 handler may be registered.
func TestConfigureHTTP2DefaultsLeaveStdlib(t *testing.T) {
	lg := h2TestLogger(t)

	r := &Router{Option: &RouterOption{Logger: lg}}
	srv := &http.Server{}
	if err := r.configureHTTP2(srv); err != nil {
		t.Fatalf("configureHTTP2: %v", err)
	}
	if srv.TLSNextProto != nil {
		t.Fatal("default options must not install the x/net HTTP/2 server")
	}

	r = &Router{Option: &RouterOption{Logger: lg, DisableHttp2: true, H2MaxConcurrentStreams: 10}}
	srv = &http.Server{}
	if err := r.configureHTTP2(srv); err != nil {
		t.Fatalf("configureHTTP2: %v", err)
	}
	if srv.TLSNextProto == nil || len(srv.TLSNextProto) != 0 {
		t.Fatal("DisableHttp2 must leave an empty, non-nil TLSNextProto")
	}
}

// With an H2 option set the x/net server is the one serving h2. It must still
// complete a normal request with a body after the dependency upgrade.
func TestConfigureHTTP2OverrideServesH2(t *testing.T) {
	r := &Router{Option: &RouterOption{
		Logger:                         h2TestLogger(t),
		H2MaxConcurrentStreams:         8,
		H2MaxUploadBufferPerConnection: 1 << 20,
		H2MaxUploadBufferPerStream:     1 << 18,
	}}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		w.Header().Set("X-Proto", req.Proto)
		w.Write(body)
	}))
	if err := r.configureHTTP2(ts.Config); err != nil {
		t.Fatalf("configureHTTP2: %v", err)
	}
	if ts.Config.TLSNextProto["h2"] == nil {
		t.Fatal("H2 options set but no h2 handler was installed")
	}
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	payload := make([]byte, 300_000) //larger than the per-stream window, forces flow-control updates
	for i := range payload {
		payload[i] = byte(i)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL, io.NopCloser(&sliceReader{b: payload}))
	req.Trailer = http.Header{"X-Trailer": nil}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}
	if len(got) != len(payload) {
		t.Fatalf("echoed %d bytes, want %d", len(got), len(payload))
	}
}

type sliceReader struct {
	b []byte
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

func h2TestLogger(t *testing.T) *logger.Logger {
	t.Helper()
	lg, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return lg
}
