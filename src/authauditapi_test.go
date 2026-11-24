package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/notify"
)

// Issue #216: opt-in auto-tagging when the login of a rule is saved, and the auth.drift report.

func setupAuthAuditTest(t *testing.T) (router *dynamicproxy.Router, events func() []string) {
	t.Helper()
	router = setupEditTest(t)
	events = setupNotifyGlueTest(t)
	sysdb.NewTable("settings")
	return router, events
}

func authAuditPost(t *testing.T, h http.HandlerFunc, values url.Values) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/authaudit/x", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return strings.TrimSpace(w.Body.String())
}

type authAuditReply struct {
	Rows    []dynamicproxy.AuthAuditRow
	AutoTag bool
	Drift   []string
}

func authAuditGet(t *testing.T) authAuditReply {
	t.Helper()
	w := httptest.NewRecorder()
	HandleAuthAuditGet(w, httptest.NewRequest(http.MethodGet, "/api/authaudit/get", nil))
	var out authAuditReply
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	return out
}

func tagsOf(t *testing.T, router *dynamicproxy.Router) string {
	t.Helper()
	ep, err := router.LoadProxy("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(ep.Tags, ",")
}

func TestAuthAutoTagOnSaveIsOptIn(t *testing.T) {
	router, _ := setupAuthAuditTest(t)

	// default: off, an edit that changes the login leaves the tags alone
	if got := authAuditGet(t); got.AutoTag || len(got.Drift) != 0 {
		t.Fatalf("fresh install: AutoTag %v Drift %v", got.AutoTag, got.Drift)
	}
	if body := postEdit(t, url.Values{"rootname": {"app.example.com"}, "authprovider": {"0"}}); body != `"OK"` {
		t.Fatal(body)
	}
	if got := tagsOf(t, router); got != "keep,me" {
		t.Fatalf("auto-tagging must be off by default, tags %q", got)
	}

	if body := authAuditPost(t, HandleAuthAuditSetAutoTag, url.Values{}); !strings.Contains(body, "error") {
		t.Fatalf("missing enable must be refused: %s", body)
	}
	if body := authAuditPost(t, HandleAuthAuditSetAutoTag, url.Values{"enable": {"true"}}); body != `"OK"` {
		t.Fatal(body)
	}
	if !authAuditGet(t).AutoTag {
		t.Fatal("setting not stored")
	}

	// on: the tag follows a login chosen in the request, other tags are kept
	postEdit(t, url.Values{"rootname": {"app.example.com"}, "authprovider": {"1"}})
	if got := tagsOf(t, router); got != "keep,me,auth:basic" {
		t.Fatalf("tags %q", got)
	}
	postEdit(t, url.Values{"rootname": {"app.example.com"}, "authprovider": {"2"}, "tags": {"keep,auth:basic,auth:stale"}})
	if got := tagsOf(t, router); got != "keep,auth:forward" {
		t.Fatalf("tags %q", got)
	}
	// an edit without the provider never touches the tag (it keeps recording the intended login)
	postEdit(t, url.Values{"rootname": {"app.example.com"}, "tags": {"keep,auth:oauth2"}})
	if got := tagsOf(t, router); got != "keep,auth:oauth2" {
		t.Fatalf("tags %q", got)
	}
	if got := authAuditGet(t); len(got.Drift) != 1 || got.Drift[0] != "app.example.com" {
		t.Fatalf("drift %v", got.Drift)
	}

	// the default site is never tagged
	root := &dynamicproxy.ProxyEndpoint{ProxyType: dynamicproxy.ProxyTypeRoot, RootOrMatchingDomain: "/"}
	autoTagAuthOnSave(root)
	if len(root.Tags) != 0 {
		t.Fatalf("root tagged: %v", root.Tags)
	}
}

func TestAuthDriftNotifiedOncePerState(t *testing.T) {
	router, events := setupAuthAuditTest(t)
	if _, err := notifyManager.SaveChannel(notify.ChannelConfig{Name: "rec", Type: notify.ChanNtfy, Enabled: true, AllowPrivate: true,
		Events: []string{notify.EventAuthDrift}, Settings: map[string]string{"server": recv(t), "topic": "t"}}); err != nil {
		t.Fatal(err)
	}
	// a second destination without an event list: auth.drift is opt-in, it must not get it
	if _, err := notifyManager.SaveChannel(notify.ChannelConfig{Name: "all", Type: notify.ChanNtfy, Enabled: true, AllowPrivate: true,
		Settings: map[string]string{"server": recv(t), "topic": "t"}}); err != nil {
		t.Fatal(err)
	}
	drifts := func() int {
		n := 0
		for _, e := range events() {
			if strings.HasPrefix(e, notify.EventAuthDrift+"|app.example.com|") {
				n++
			}
		}
		return n
	}
	check := func() []string { return checkAuthDrift(router.AuditAllAuth()) }

	if got := check(); len(got) != 0 || drifts() != 0 {
		t.Fatalf("untagged rule reported: %v", got)
	}
	// tagged as it is: no drift
	authAuditPost(t, HandleAuthAuditAutoTag, url.Values{"ep": {"app.example.com"}})
	if got := tagsOf(t, router); got != "keep,me,auth:basic" {
		t.Fatalf("tags %q", got)
	}
	if got := check(); len(got) != 0 || drifts() != 0 {
		t.Fatalf("matching tag reported: %v", got)
	}

	// the reporter's case: the method is lost, the tag still says basic
	if err := applyNetworkingChange("app.example.com", func(e *dynamicproxy.ProxyEndpoint) error {
		e.AuthenticationProvider.AuthMethod = dynamicproxy.AuthMethodNone
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := check(); len(got) != 1 || drifts() != 1 {
		t.Fatalf("drift %v, %d event(s): %v", got, drifts(), events())
	}
	check()
	authAuditGet(t)
	if drifts() != 1 {
		t.Fatalf("the same drift must be announced once, got %d", drifts())
	}
	row := authAuditGet(t).Rows[0]
	if !row.TagDrift || row.Method != "none" || strings.Join(row.AuthTags, ",") != "auth:basic" {
		t.Fatalf("row %+v", row)
	}

	// another drifting state of the same rule is news
	applyNetworkingChange("app.example.com", func(e *dynamicproxy.ProxyEndpoint) error {
		e.AuthenticationProvider.AuthMethod = dynamicproxy.AuthMethodForward
		return nil
	})
	if check(); drifts() != 2 {
		t.Fatalf("changed drift: %d event(s)", drifts())
	}

	// "Fix tag" ends it, and a drift that comes back is announced again
	if body := authAuditPost(t, HandleAuthAuditAutoTag, url.Values{"ep": {"app.example.com"}}); !strings.Contains(body, `"Changed":1`) {
		t.Fatal(body)
	}
	if got := check(); len(got) != 0 || drifts() != 2 {
		t.Fatalf("after fix: %v, %d", got, drifts())
	}
	applyNetworkingChange("app.example.com", func(e *dynamicproxy.ProxyEndpoint) error {
		e.AuthenticationProvider.AuthMethod = dynamicproxy.AuthMethodNone
		return nil
	})
	if check(); drifts() != 3 {
		t.Fatalf("returned drift: %d event(s)", drifts())
	}
	for _, e := range events() {
		if !strings.HasPrefix(e, notify.EventAuthDrift+"|") {
			t.Fatalf("unexpected event %s", e)
		}
	}
	for _, d := range notifyManager.Deliveries() {
		if d.Channel == "all" && d.Event == notify.EventAuthDrift {
			t.Fatalf("opt-in event delivered to a destination that did not list it: %+v", d)
		}
	}
}

// Drift that exists while no destination lists auth.drift (an upgrade, a page load before the admin ticked the
// event) must not be remembered as announced: it is sent once somebody subscribes.
func TestAuthDriftWaitsForASubscriber(t *testing.T) {
	router, events := setupAuthAuditTest(t)
	if err := applyNetworkingChange("app.example.com", func(e *dynamicproxy.ProxyEndpoint) error {
		e.Tags = []string{"auth:oauth2"}
		e.AuthenticationProvider.AuthMethod = dynamicproxy.AuthMethodNone
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// a destination without an event list does not count: the event is opt-in
	if _, err := notifyManager.SaveChannel(notify.ChannelConfig{Name: "all", Type: notify.ChanNtfy, Enabled: true, AllowPrivate: true,
		Settings: map[string]string{"server": recv(t), "topic": "t"}}); err != nil {
		t.Fatal(err)
	}
	if got := checkAuthDrift(router.AuditAllAuth()); len(got) != 1 {
		t.Fatalf("drift %v", got)
	}
	if got := authAuditGet(t); len(got.Drift) != 1 {
		t.Fatalf("drift %v", got.Drift)
	}
	stored := map[string]string{}
	sysdb.Read("settings", authDriftAnnouncedKey, &stored)
	if len(events()) != 0 || len(stored) != 0 {
		t.Fatalf("nobody subscribed: events %v, remembered %v", events(), stored)
	}

	if _, err := notifyManager.SaveChannel(notify.ChannelConfig{Name: "rec", Type: notify.ChanNtfy, Enabled: true, AllowPrivate: true,
		Events: []string{notify.EventAuthDrift}, Settings: map[string]string{"server": recv(t), "topic": "t"}}); err != nil {
		t.Fatal(err)
	}
	checkAuthDrift(router.AuditAllAuth())
	checkAuthDrift(router.AuditAllAuth())
	if got := events(); len(got) != 1 || !strings.HasPrefix(got[0], notify.EventAuthDrift+"|app.example.com|") {
		t.Fatalf("the drift that was already there must be sent once after subscribing: %v", got)
	}
}

// Fix tag for one rule: an unknown rule is an error, a rule whose tag already matches reports Changed 0, and the
// reply names the tag that was set (the caller's copy of the audit may be out of date).
func TestAuthAutoTagOneRuleReply(t *testing.T) {
	router, _ := setupAuthAuditTest(t)
	if body := authAuditPost(t, HandleAuthAuditAutoTag, url.Values{"ep": {"gone.example.com"}}); !strings.Contains(body, "error") {
		t.Fatalf("unknown rule must be refused: %s", body)
	}
	if got := tagsOf(t, router); got != "keep,me" {
		t.Fatalf("tags %q", got)
	}
	if body := authAuditPost(t, HandleAuthAuditAutoTag, url.Values{"ep": {"app.example.com"}}); !strings.Contains(body, `"Changed":1`) || !strings.Contains(body, `"Tag":"auth:basic"`) {
		t.Fatal(body)
	}
	if body := authAuditPost(t, HandleAuthAuditAutoTag, url.Values{"ep": {"app.example.com"}}); !strings.Contains(body, `"Changed":0`) || !strings.Contains(body, `"Tag":"auth:basic"`) {
		t.Fatal(body)
	}
	if body := authAuditPost(t, HandleAuthAuditAutoTag, url.Values{}); !strings.Contains(body, `"Changed":0`) || strings.Contains(body, "Tag") {
		t.Fatal(body)
	}
}
