package wintty

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

/*
	Host key verification for wintty

	The remote host key is checked against a known_hosts file before any
	credential is sent. Unknown hosts need an explicit trust-on-first-use
	confirmation from the user, a changed host key is always refused.
*/

// How long the user has to answer the host key confirmation prompt
const hostKeyConfirmTimeout = 60 * time.Second

// HostKeyConfirmFunc asks the user whether an unknown host key should be
// trusted. It must return true only on an explicit approval.
type HostKeyConfirmFunc func(hostname string, keyType string, fingerprint string) (bool, error)

// knownHostsMu serializes access to the known_hosts file(s) across servers
var knownHostsMu sync.Mutex

// hostKeyCallback returns a ssh.HostKeyCallback that verifies the remote host
// key against the configured known_hosts file. The callback runs during the
// key exchange, that is before any authentication method is attempted, so a
// rejected key means the password never leaves this process.
func (s *Server) hostKeyCallback(confirm HostKeyConfirmFunc) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		path := s.config.KnownHostsFile
		if path != "" {
			known, err := checkKnownHost(path, hostname, remote, key)
			if err != nil || known {
				return err
			}
		}

		//Unknown host, ask the user (trust on first use). The known hosts lock
		//is not held here so a pending prompt does not block other sessions.
		if confirm == nil {
			return fmt.Errorf("unknown host key for %s and no way to confirm it", hostname)
		}
		accepted, err := confirm(hostname, key.Type(), ssh.FingerprintSHA256(key))
		if err != nil {
			return fmt.Errorf("host key confirmation failed: %v", err)
		}
		if !accepted {
			return fmt.Errorf("host key for %s was not trusted by user", hostname)
		}

		if path == "" {
			//Nowhere to persist, trust for this connection only
			return nil
		}

		knownHostsMu.Lock()
		defer knownHostsMu.Unlock()
		//Re-check: another session may have recorded a key for this host
		//while the user was answering the prompt
		known, err := checkKnownHostLocked(path, hostname, remote, key)
		if err != nil || known {
			return err
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("unable to save host key: %v", err)
		}
		defer f.Close()
		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
		if _, err := f.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("unable to save host key: %v", err)
		}
		logf("trusted new host key for %s (%s %s)", hostname, key.Type(), ssh.FingerprintSHA256(key))
		return nil
	}
}

// checkKnownHost reports whether key is on record for hostname. It returns an
// error for a mismatching or revoked key and (false, nil) for an unknown host.
func checkKnownHost(path string, hostname string, remote net.Addr, key ssh.PublicKey) (bool, error) {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()
	return checkKnownHostLocked(path, hostname, remote, key)
}

// checkKnownHostLocked is checkKnownHost with knownHostsMu already held
func checkKnownHostLocked(path string, hostname string, remote net.Addr, key ssh.PublicKey) (bool, error) {
	if err := ensureKnownHostsFile(path); err != nil {
		return false, fmt.Errorf("unable to prepare known hosts file: %v", err)
	}
	check, err := knownhosts.New(path)
	if err != nil {
		return false, fmt.Errorf("unable to read known hosts file: %v", err)
	}

	err = check(hostname, remote, key)
	if err == nil {
		//Known host with matching key
		return true, nil
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		//Revoked key or other failure
		return false, err
	}
	if len(keyErr.Want) > 0 {
		//There is a key on record for this host and it is not this one
		logf("host key mismatch for %s, presented %s %s", hostname, key.Type(), ssh.FingerprintSHA256(key))
		return false, fmt.Errorf("HOST KEY MISMATCH for %s: the server presented %s key %s which differs from the key on record. "+
			"This can mean someone is intercepting the connection. Connection refused and no password was sent. "+
			"If the host key was changed on purpose, remove the entry for this host from %s and connect again",
			hostname, key.Type(), ssh.FingerprintSHA256(key), path)
	}
	return false, nil
}

// ensureKnownHostsFile creates an empty known_hosts file if it does not exist
func ensureKnownHostsFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0775); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}

// confirmHostKeyOverWebSocket shows the host key fingerprint in the web
// terminal and waits for the user to accept or reject it
func confirmHostKeyOverWebSocket(conn *websocket.Conn) HostKeyConfirmFunc {
	return func(hostname string, keyType string, fingerprint string) (bool, error) {
		req, _ := json.Marshal(map[string]string{
			"type":        "hostkey_confirm",
			"host":        hostname,
			"keyType":     keyType,
			"fingerprint": fingerprint,
		})
		if err := conn.WriteMessage(websocket.TextMessage, req); err != nil {
			return false, err
		}

		conn.SetReadDeadline(time.Now().Add(hostKeyConfirmTimeout))
		defer conn.SetReadDeadline(time.Time{})
		_, message, err := conn.ReadMessage()
		if err != nil {
			return false, err
		}

		var resp struct {
			Type   string `json:"type"`
			Accept bool   `json:"accept"`
		}
		if err := json.Unmarshal(message, &resp); err != nil || resp.Type != "hostkey_response" {
			return false, errors.New("invalid host key confirmation message")
		}
		return resp.Accept, nil
	}
}
