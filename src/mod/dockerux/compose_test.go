package dockerux

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The shipped docker files live outside the Go module (../../../docker).
// They are not present when only src/ is copied (e.g. the image build), so
// the tests skip in that case.
func readDockerFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docker", name))
	if os.IsNotExist(err) {
		t.Skipf("docker/%s not available in this checkout", name)
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// activeLines returns the file without comments and blank lines.
func activeLines(content string) []string {
	out := []string{}
	for _, line := range strings.Split(content, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// serviceBlock returns the active lines of one top-level compose service.
func serviceBlock(t *testing.T, content string, service string) []string {
	t.Helper()
	out := []string{}
	in := false
	for _, line := range activeLines(content) {
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent <= 2 {
			in = indent == 2 && strings.TrimSpace(line) == service+":"
			continue
		}
		if in {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatalf("service %q not found", service)
	}
	return out
}

// The default compose file must not hand the Docker socket to Dunree:
// socket access is root-equivalent on the host.
func TestDefaultComposeDoesNotMountDockerSocket(t *testing.T) {
	for _, line := range activeLines(readDockerFile(t, "docker-compose.yml")) {
		if strings.Contains(line, "docker.sock") {
			t.Errorf("default compose mounts the Docker socket: %q", strings.TrimSpace(line))
		}
		if strings.Contains(line, "privileged") {
			t.Errorf("default compose must not be privileged: %q", strings.TrimSpace(line))
		}
	}
}

// The opt-in override must keep the socket away from the Dunree container
// and only allow read (GET) access through the proxy.
func TestSocketProxyOverrideIsReadOnly(t *testing.T) {
	content := readDockerFile(t, "docker-compose.socket-proxy.yml")

	svc := strings.Join(serviceBlock(t, content, "dunree"), "\n")
	if strings.Contains(svc, "docker.sock") {
		t.Error("override mounts the Docker socket into the dunree service")
	}
	if !strings.Contains(svc, `DOCKER_HOST: "tcp://docker-socket-proxy:2375"`) {
		t.Error("dunree service is not pointed at the socket proxy")
	}

	proxy := serviceBlock(t, content, "docker-socket-proxy")
	joined := strings.Join(proxy, "\n")
	if !strings.Contains(joined, `POST: "0"`) {
		t.Error("socket proxy must reject write requests (POST: \"0\")")
	}
	if strings.Contains(joined, "ports:") {
		t.Error("socket proxy must not publish ports")
	}
	// Only the endpoints dockerux needs may be switched on.
	allowed := map[string]bool{"CONTAINERS": true, "NETWORKS": true}
	enabled := regexp.MustCompile(`^\s+([A-Z_]+):\s*"?(1|true)"?\s*$`)
	for _, line := range proxy {
		if m := enabled.FindStringSubmatch(line); m != nil && !allowed[m[1]] {
			t.Errorf("socket proxy enables unexpected API section %s", m[1])
		}
	}
}

// The runtime image must not ship privilege-escalation / remote-shell tools.
func TestRuntimeImageHasNoSudoOrSSH(t *testing.T) {
	content := readDockerFile(t, "Dockerfile")
	final := content[strings.LastIndex(content, "\nFROM "):]
	pkg := regexp.MustCompile(`(^|\s)(sudo|openssh|openssh-server|openssh-client)(\s|$)`)
	for _, line := range activeLines(final) {
		if strings.Contains(line, "apk add") && pkg.MatchString(line) {
			t.Errorf("runtime image installs sudo/openssh: %q", strings.TrimSpace(line))
		}
	}
}
