package wintty

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// fakeSSHServer is a minimal SSH server that records every password it is
// offered. Its host key can be swapped to simulate a spoofed target.
type fakeSSHServer struct {
	ln        net.Listener
	mu        sync.Mutex
	signer    ssh.Signer
	passwords []string
	active    int        // server side connections still in progress, guarded by mu
	idle      *sync.Cond // signalled when active drops to 0
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newFakeSSHServer(t *testing.T) *fakeSSHServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSSHServer{ln: ln, signer: newSigner(t)}
	f.idle = sync.NewCond(&f.mu)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			//Counted before the handshake starts, so a client Dial that returned
			//is always covered by seenPasswords
			f.mu.Lock()
			f.active++
			f.mu.Unlock()
			go func() {
				defer func() {
					f.mu.Lock()
					f.active--
					if f.active == 0 {
						f.idle.Broadcast()
					}
					f.mu.Unlock()
				}()
				defer c.Close()
				cfg := &ssh.ServerConfig{
					PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
						f.mu.Lock()
						f.passwords = append(f.passwords, string(password))
						f.mu.Unlock()
						return nil, nil
					},
				}
				f.mu.Lock()
				cfg.AddHostKey(f.signer)
				f.mu.Unlock()
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						ch.Reject(ssh.Prohibited, "test server")
					}
				}()
				sc.Wait()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSSHServer) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

// seenPasswords waits for all server side handshakes to end and returns
// the passwords the server received so far
func (f *fakeSSHServer) seenPasswords() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.active > 0 {
		f.idle.Wait()
	}
	return append([]string(nil), f.passwords...)
}

func (f *fakeSSHServer) setSigner(s ssh.Signer) {
	f.mu.Lock()
	f.signer = s
	f.mu.Unlock()
}

// dial runs the same handshake as connectSSH and closes the client again
func dial(s *Server, password string, confirm HostKeyConfirmFunc) error {
	addr := net.JoinHostPort(s.config.RemoteAddr, strconv.Itoa(s.config.RemotePort))
	client, err := ssh.Dial("tcp", addr, s.sshClientConfig(password, confirm))
	if err != nil {
		return err
	}
	return client.Close()
}

func TestHostKeyVerification(t *testing.T) {
	const password = "s3cret-password"
	fake := newFakeSSHServer(t)
	khFile := filepath.Join(t.TempDir(), "conf", "webssh_known_hosts")
	s := NewServer(Config{RemoteAddr: "127.0.0.1", RemotePort: fake.port(), Username: "admin", KnownHostsFile: khFile}, 0)

	var prompts int32
	var shownFingerprint string
	answer := false
	confirm := func(hostname, keyType, fingerprint string) (bool, error) {
		atomic.AddInt32(&prompts, 1)
		shownFingerprint = fingerprint
		return answer, nil
	}

	// 1. Unknown host, user declines: no password, nothing persisted
	if err := dial(s, password, confirm); err == nil {
		t.Fatal("expected connection to fail when the host key is not trusted")
	}
	if prompts != 1 {
		t.Fatalf("expected 1 prompt, got %d", prompts)
	}
	if want := ssh.FingerprintSHA256(fake.signer.PublicKey()); shownFingerprint != want {
		t.Fatalf("prompt showed fingerprint %q, want %q", shownFingerprint, want)
	}
	if got := fake.seenPasswords(); len(got) != 0 {
		t.Fatalf("password was sent to an untrusted host: %v", got)
	}
	if data, _ := os.ReadFile(khFile); len(strings.TrimSpace(string(data))) != 0 {
		t.Fatalf("rejected host key was persisted: %s", data)
	}

	// 2. Unknown host, user accepts: connects and the key is persisted
	answer = true
	if err := dial(s, password, confirm); err != nil {
		t.Fatalf("expected connection to succeed after trusting the key: %v", err)
	}
	if prompts != 2 {
		t.Fatalf("expected 2 prompts, got %d", prompts)
	}
	if got := fake.seenPasswords(); len(got) != 1 || got[0] != password {
		t.Fatalf("expected the password to reach the trusted host once, got %v", got)
	}
	if data, _ := os.ReadFile(khFile); !strings.Contains(string(data), "ssh-ed25519") {
		t.Fatalf("trusted host key was not persisted: %q", data)
	}

	// 3. Known host: no prompt (also with a fresh server reading the same file)
	s = NewServer(s.config, 0)
	if err := dial(s, password, confirm); err != nil {
		t.Fatalf("expected known host to connect: %v", err)
	}
	if prompts != 2 {
		t.Fatalf("known host must not prompt again, got %d prompts", prompts)
	}

	// 4. Host key changed (spoofed target): refuse, do not prompt, no password
	before := len(fake.seenPasswords())
	fake.setSigner(newSigner(t))
	err := dial(s, password, confirm)
	if err == nil {
		t.Fatal("expected connection to a host with a changed key to be refused")
	}
	if !strings.Contains(err.Error(), "HOST KEY MISMATCH") {
		t.Fatalf("expected a host key mismatch error, got: %v", err)
	}
	if prompts != 2 {
		t.Fatalf("a changed host key must not be offered for confirmation, got %d prompts", prompts)
	}
	if got := fake.seenPasswords(); len(got) != before {
		t.Fatalf("password was sent to a host with a changed key: %v", got)
	}
}

func TestHostKeyNoKnownHostsFileAlwaysPrompts(t *testing.T) {
	fake := newFakeSSHServer(t)
	s := NewServer(Config{RemoteAddr: "127.0.0.1", RemotePort: fake.port(), Username: "admin"}, 0)

	if err := dial(s, "pw", nil); err == nil {
		t.Fatal("expected failure without any way to confirm the host key")
	}
	prompts := 0
	confirm := func(string, string, string) (bool, error) { prompts++; return true, nil }
	for i := 0; i < 2; i++ {
		if err := dial(s, "pw", confirm); err != nil {
			t.Fatal(err)
		}
	}
	if prompts != 2 {
		t.Fatalf("expected a prompt on every connection, got %d", prompts)
	}
	if got := fake.seenPasswords(); len(got) != 2 {
		t.Fatalf("expected 2 authenticated connections, got %v", got)
	}
}

// End to end over the WebSocket: the fingerprint is shown to the web client
// and the password is held back when the user rejects it
func TestWebSocketHostKeyPromptRejected(t *testing.T) {
	fake := newFakeSSHServer(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	khFile := filepath.Join(t.TempDir(), "known_hosts")
	s := NewServer(Config{RemoteAddr: "127.0.0.1", RemotePort: fake.port(), Username: "admin", KnownHostsFile: khFile}, listenPort)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	ws, _, err := websocket.DefaultDialer.Dial("ws://127.0.0.1:"+strconv.Itoa(listenPort)+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))

	read := func() map[string]string {
		t.Helper()
		_, data, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("websocket read: %v", err)
		}
		msg := map[string]string{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("unexpected message %q: %v", data, err)
		}
		return msg
	}

	if msg := read(); msg["type"] != "auth_required" {
		t.Fatalf("expected auth_required, got %v", msg)
	}
	ws.WriteJSON(map[string]string{"type": "auth", "password": "s3cret-password"})

	msg := read()
	if msg["type"] != "hostkey_confirm" {
		t.Fatalf("expected hostkey_confirm, got %v", msg)
	}
	if want := ssh.FingerprintSHA256(fake.signer.PublicKey()); msg["fingerprint"] != want {
		t.Fatalf("fingerprint %q, want %q", msg["fingerprint"], want)
	}
	ws.WriteJSON(map[string]interface{}{"type": "hostkey_response", "accept": false})

	if msg := read(); msg["error"] == "" {
		t.Fatalf("expected an error after rejecting the host key, got %v", msg)
	}
	if got := fake.seenPasswords(); len(got) != 0 {
		t.Fatalf("password was sent although the host key was rejected: %v", got)
	}
}

// A pending host key prompt must not hold the known hosts lock, otherwise one
// unanswered prompt blocks every other Web SSH session for up to a minute
func TestHostKeyPromptDoesNotHoldLock(t *testing.T) {
	fake := newFakeSSHServer(t)
	khFile := filepath.Join(t.TempDir(), "known_hosts")
	s := NewServer(Config{RemoteAddr: "127.0.0.1", RemotePort: fake.port(), Username: "admin", KnownHostsFile: khFile}, 0)

	confirm := func(hostname, keyType, fingerprint string) (bool, error) {
		done := make(chan struct{})
		go func() {
			knownHostsMu.Lock()
			knownHostsMu.Unlock()
			close(done)
		}()
		select {
		case <-done:
			return true, nil
		case <-time.After(2 * time.Second):
			return false, errors.New("known hosts lock held while waiting for the user")
		}
	}
	if err := dial(s, "pw", confirm); err != nil {
		t.Fatal(err)
	}
}
