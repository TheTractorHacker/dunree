// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package wirecompat

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestUserAgentFollowsTheLegacySwitch(t *testing.T) {
	defer SetEmitLegacy(true)
	SetEmitLegacy(true)
	if g := UserAgent("Dunree-HealthCheck", "Zoraxy-HealthCheck"); g != "Dunree-HealthCheck (Zoraxy-HealthCheck)" { // legacy-compat
		t.Errorf("on: %q", g)
	}
	SetEmitLegacy(false)
	if g := UserAgent("Dunree-HealthCheck", "Zoraxy-HealthCheck"); g != "Dunree-HealthCheck" { // legacy-compat
		t.Errorf("off: %q", g)
	}
	if g := UserAgent("dunree-x/1", ""); g != "dunree-x/1" {
		t.Errorf("no legacy token: %q", g)
	}
}

func TestEnvFollowsTheLegacySwitch(t *testing.T) {
	defer SetEmitLegacy(true)
	pairs := [][2]string{{"EVENT", "a=b"}, {"CA", ""}}
	SetEmitLegacy(true)
	if g := strings.Join(Env(pairs), "|"); g != "DUNREE_EVENT=a=b|DUNREE_CA=|ZORAXY_EVENT=a=b|ZORAXY_CA=" { // legacy-compat
		t.Errorf("on: %s", g)
	}
	SetEmitLegacy(false)
	if g := strings.Join(Env(pairs), "|"); g != "DUNREE_EVENT=a=b|DUNREE_CA=" {
		t.Errorf("off: %s", g)
	}
}

// Every outbound User-Agent that carried the inherited token now goes through UserAgent, so the
// Dunree token is always sent and the old one follows the switch (plan row 13).
func TestNoRawLegacyUserAgentInTheSource(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	token := regexp.MustCompile(`"[Zz]oraxy-(?:HealthCheck|Webhook|Notify|Sablier|HTTPTest|blocklist-import|updater|cluster/|fleet/|wsproxy/|aiassist/|crowdsec-bouncer/|uptime/)`) // legacy-compat
	var bad []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "node_modules" || (strings.HasPrefix(n, ".") && p != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, _ := os.ReadFile(p)
		for i, line := range strings.Split(string(b), "\n") {
			if token.MatchString(line) && !strings.Contains(line, "UserAgent(\"") {
				bad = append(bad, p+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if len(bad) > 0 {
		t.Fatalf("User-Agent with only the inherited token (use wirecompat.UserAgent):\n%s", strings.Join(bad, "\n"))
	}
}

func TestCookieFallsBackToTheLegacyName(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.AddCookie(&http.Cookie{Name: "zoraxy_captcha_session", Value: "old"})                                      // legacy-compat
	if c, err := Cookie(r, "dunree_captcha_session", "zoraxy_captcha_session"); err != nil || c.Value != "old" { // legacy-compat
		t.Fatalf("legacy cookie not honoured: %v %v", c, err)
	}
	r.AddCookie(&http.Cookie{Name: "dunree_captcha_session", Value: "new"})
	if c, _ := Cookie(r, "dunree_captcha_session", "zoraxy_captcha_session"); c.Value != "new" { // legacy-compat
		t.Fatalf("the new cookie must win: %v", c)
	}
	r2, _ := http.NewRequest("GET", "http://x/", nil)
	if _, err := Cookie(r2, "a", "b"); err == nil {
		t.Fatal("no cookie: want an error")
	}
}
