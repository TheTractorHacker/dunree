package dynamicproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/info/logger"
)

func drainRouter(t *testing.T, h http.Handler) (*Router, string) {
	t.Helper()
	lg, _ := logger.NewFmtLogger()
	r := &Router{Option: &RouterOption{Logger: lg}, secondaryServers: map[string]*http.Server{}, secondaryStopChans: map[string]chan bool{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	r.server = srv
	r.Running = true
	return r, ln.Addr().String()
}

// an in-flight request finishes during the drain; new connections are refused as soon as the stop begins
func TestStopProxyServiceWithinWaitsForInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	r, addr := drainRouter(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "finished")
	}))
	var wg sync.WaitGroup
	var body string
	var getErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			getErr = err
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body = string(b)
	}()
	<-started
	stopped := make(chan time.Duration, 1)
	t0 := time.Now()
	go func() { r.StopProxyServiceWithin(5 * time.Second); stopped <- time.Since(t0) }()

	time.Sleep(300 * time.Millisecond)
	select {
	case <-stopped:
		t.Fatal("stop returned while a request was still in flight")
	default:
	}
	if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		c.Close()
		t.Error("the listener still accepts connections while draining")
	}
	close(release)
	wg.Wait()
	if getErr != nil || body != "finished" {
		t.Fatalf("in-flight request was cut: %v %q", getErr, body)
	}
	select {
	case d := <-stopped:
		if d > 3*time.Second {
			t.Errorf("stop took %v after the request finished", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stop never finished")
	}
	if r.Running {
		t.Error("router still marked running")
	}
}

// a request that never ends is cut at the deadline
func TestStopProxyServiceWithinForceClosesAtDeadline(t *testing.T) {
	started := make(chan struct{})
	r, addr := drainRouter(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(started)
		<-req.Context().Done() //never finishes on its own
	}))
	errc := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		errc <- err
	}()
	<-started
	t0 := time.Now()
	r.StopProxyServiceWithin(600 * time.Millisecond)
	el := time.Since(t0)
	if el < 500*time.Millisecond {
		t.Errorf("did not wait for the drain deadline: %v", el)
	}
	if el > 3*time.Second {
		t.Errorf("deadline not enforced: %v", el)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Error("the stuck request should have been cut")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client connection was never closed")
	}
}

// secondary and port 80 listeners drain with the same deadline
func TestStopProxyServiceWithinDrainsSecondaryListeners(t *testing.T) {
	r, _ := drainRouter(t, http.NotFoundHandler())
	started := make(chan struct{})
	release := make(chan struct{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	sec := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "sec-done")
	})}
	go sec.Serve(ln)
	stop := make(chan bool)
	r.secondaryServers["x"] = sec
	r.secondaryStopChans["x"] = stop
	r.drainWG.Add(1)
	go func() {
		defer r.drainWG.Done()
		<-stop
		ctx, cancel := contextWithTimeout(r.drainFor(5 * time.Second))
		defer cancel()
		if sec.Shutdown(ctx) != nil && r.drainTimeout.Load() > 0 {
			sec.Close()
		}
	}()
	res := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			res <- "err"
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		res <- string(b)
	}()
	<-started
	done := make(chan struct{})
	go func() { r.StopProxyServiceWithin(5 * time.Second); close(done) }()
	time.Sleep(300 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("returned before the secondary request finished")
	default:
	}
	close(release)
	if got := <-res; got != "sec-done" {
		t.Fatalf("secondary request was cut: %q", got)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("never finished")
	}
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// once the stop has begun nothing may bind a listener again: an admin or Fleet action during the drain must fail
func TestNothingRebindsListenersWhileStopping(t *testing.T) {
	r, _ := drainRouter(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	if err := r.StopProxyServiceWithin(time.Second); err != nil {
		t.Logf("stop: %v", err)
	}
	r.Running = true //an admin action that thinks the proxy is up
	if err := r.Restart(); err != ErrProxyStopping {
		t.Errorf("Restart during shutdown: %v", err)
	}
	r.server = nil
	if err := r.StartProxyService(); err != ErrProxyStopping {
		t.Errorf("StartProxyService during shutdown: %v", err)
	}
	before := len(r.secondaryServers)
	r.UpdateSecondaryListeners()
	if len(r.secondaryServers) != before || r.server != nil {
		t.Error("a listener was started while the process is stopping")
	}
}
