package zorxauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// two nodes with their own database and the same user list
func newSharedPair(t *testing.T, keyA, keyB string) (*AuthRouter, *GatewayServer, *AuthRouter, *GatewayServer) {
	t.Helper()
	a, ga := newTestGateway(t)
	b, gb := newTestGateway(t)
	for _, table := range []string{DB_NAME, DB_BROWSER_SESSIONS_TABLE, DB_GATEWAY_SESSIONS_TABLE} {
		a.Database.NewTable(table)
		b.Database.NewTable(table)
	}
	a.SetSharedSessionKey([]byte(keyA))
	b.SetSharedSessionKey([]byte(keyB))
	return a, ga, b, gb
}

func withCookie(ar *AuthRouter, method, target, value string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.AddCookie(&http.Cookie{Name: ar.Options.CookieName, Value: value})
	return req
}

func cookieFrom(t *testing.T, ar *AuthRouter, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == ar.Options.CookieName {
			return c.Value
		}
	}
	t.Fatal("no session cookie set")
	return ""
}

func TestSharedSessions_DefaultStaysRandomAndPerNode(t *testing.T) {
	a, _, b, _ := newSharedPair(t, "", "")
	if a.SharedSessionsEnabled() {
		t.Fatal("shared sessions must be off without a key")
	}
	tok := a.issueSessionToken(tokenKindGateway, "alice", time.Now().Add(time.Hour), false)
	if isSharedToken(tok) || len(tok) != 64 {
		t.Fatalf("default token must be the 32 byte random id, got %q", tok)
	}
	a.gatewaySessionStore.Store(tok, &GatewaySession{Username: "alice", Expiry: time.Now().Add(time.Hour)})
	if ok, _ := a.RequestIsAuthenticatedInSSO(nil, withCookie(a, "GET", "/", tok)); !ok {
		t.Fatal("issuing node must accept its session")
	}
	if ok, _ := b.RequestIsAuthenticatedInSSO(nil, withCookie(b, "GET", "/", tok)); ok {
		t.Fatal("without a key another node must not accept the session")
	}
	code := a.generateValidationCodeForSession("alice")
	if isSharedToken(code) {
		t.Fatal("default validation code must stay a random id")
	}
	if _, ok := b.consumeValidationCode(code); ok {
		t.Fatal("without a key another node must not accept the validation code")
	}
	if u, ok := a.consumeValidationCode(code); !ok || u != "alice" {
		t.Fatal("issuing node must accept its validation code")
	}
	if _, ok := a.consumeValidationCode(code); ok {
		t.Fatal("validation code must be single use")
	}
}

func TestSharedSessions_LoginOnOneNodeIsValidOnTheOther(t *testing.T) {
	a, _, b, gb := newSharedPair(t, "k1-shared-key-material", "k1-shared-key-material")

	// portal session issued by node A (what handleLogin stores and sets as cookie)
	exp := time.Now().Add(time.Hour)
	portal := a.issueSessionToken(tokenKindGateway, "alice", exp, true)
	a.gatewaySessionStore.Store(portal, &GatewaySession{Username: "alice", Expiry: exp, RememberMe: true})
	if !isSharedToken(portal) {
		t.Fatal("with a key the cookie must be a signed token")
	}

	// node B has never seen it: the SSO fast path must still work there
	rec := httptest.NewRecorder()
	gb.handleAuthPage(rec, withCookie(b, "GET", "/?redirect="+url.QueryEscape("https://app.example.com/x"), portal))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("node B did not accept the portal session of node A: %d %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("session_id")
	if loc.Host != "app.example.com" || !isSharedToken(code) || loc.Query().Get("remember_me") != "true" {
		t.Fatalf("unexpected session-set redirect %s", loc)
	}
	var leaked int
	b.gatewaySessionStore.Range(func(_, _ any) bool { leaked++; return true })
	if leaked != 0 {
		t.Fatal("a foreign token must not be copied into the store (nothing would expire it)")
	}

	// the session-set redirect lands on node A although node B issued the code
	rec = httptest.NewRecorder()
	a.handleSessionSetCallback(rec, httptest.NewRequest("GET", loc.RequestURI(), nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("node A refused the validation code of node B: %d", rec.Code)
	}
	site := cookieFrom(t, a, rec)

	// replaying the code is refused
	rec = httptest.NewRecorder()
	a.handleSessionSetCallback(rec, httptest.NewRequest("GET", loc.RequestURI(), nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("validation code accepted twice: %d", rec.Code)
	}

	// the per host cookie of node A is valid on node B
	if !b.RequestIsAuthenticatedInHost(nil, withCookie(b, "GET", "/x", site)) {
		t.Fatal("node B refused the per host session of node A")
	}
	u, err := b.GetUserFromRequest(nil, withCookie(b, "GET", "/x", site))
	if err != nil || u.Username != "alice" {
		t.Fatalf("node B could not resolve the user: %v", err)
	}

	// a restart of node A (empty stores) keeps both sessions
	a.cookieIdStore.Delete(site)
	a.gatewaySessionStore.Delete(portal)
	if !a.RequestIsAuthenticatedInHost(nil, withCookie(a, "GET", "/x", site)) {
		t.Fatal("signed session lost with the in-memory store")
	}
	if ok, name := a.RequestIsAuthenticatedInSSO(nil, withCookie(a, "GET", "/", portal)); !ok || name != "alice" {
		t.Fatal("signed portal session lost with the in-memory store")
	}
}

func TestSharedSessions_RejectsForgedTokens(t *testing.T) {
	a, _, b, _ := newSharedPair(t, "key-of-cluster-one", "key-of-cluster-two")
	exp := time.Now().Add(time.Hour)
	portal := a.mintToken(tokenKindGateway, "alice", exp, false)
	site := a.mintToken(tokenKindBrowser, "alice", exp, false)

	if ok, _ := b.RequestIsAuthenticatedInSSO(nil, withCookie(b, "GET", "/", portal)); ok {
		t.Fatal("token signed with another key accepted")
	}
	// a per host token must not open the portal and the other way round
	if ok, _ := a.RequestIsAuthenticatedInSSO(nil, withCookie(a, "GET", "/", site)); ok {
		t.Fatal("per host token accepted as portal session")
	}
	if a.RequestIsAuthenticatedInHost(nil, withCookie(a, "GET", "/", portal)) {
		t.Fatal("portal token accepted as per host session")
	}
	if _, ok := a.consumeValidationCode(site); ok {
		t.Fatal("session token accepted as validation code")
	}
	// tampering with the payload (other user) breaks the signature
	parts := strings.Split(site, ".")
	other := strings.Split(a.mintToken(tokenKindBrowser, "mallory", exp, false), ".")
	if a.RequestIsAuthenticatedInHost(nil, withCookie(a, "GET", "/", parts[0]+"."+other[1]+"."+parts[2])) {
		t.Fatal("tampered token accepted")
	}
	for _, bad := range []string{sharedTokenPrefix, sharedTokenPrefix + ".", sharedTokenPrefix + "e30.", "zxs1.!!.??"} {
		if a.RequestIsAuthenticatedInHost(nil, withCookie(a, "GET", "/", bad)) {
			t.Fatalf("malformed token %q accepted", bad)
		}
	}
	// expired
	old := a.mintToken(tokenKindBrowser, "alice", time.Now().Add(-time.Second), false)
	if a.RequestIsAuthenticatedInHost(nil, withCookie(a, "GET", "/", old)) {
		t.Fatal("expired token accepted")
	}
	// a deleted user is refused although the signature is good
	ghost := a.mintToken(tokenKindBrowser, "ghost", exp, false)
	if _, err := a.GetUserFromRequest(nil, withCookie(a, "GET", "/", ghost)); err == nil {
		t.Fatal("token of a user that does not exist resolved to a user")
	}
}

func TestSharedSessions_LogoutAndLogoutAll(t *testing.T) {
	a, ga, b, _ := newSharedPair(t, "k1-shared-key-material", "k1-shared-key-material")
	exp := time.Now().Add(time.Hour)
	portal := a.mintToken(tokenKindGateway, "alice", exp, false)
	otherDevice := a.mintToken(tokenKindGateway, "alice", exp, false)
	site := a.mintToken(tokenKindBrowser, "alice", exp, false)

	rec := httptest.NewRecorder()
	ga.handleLogout(rec, withCookie(a, "POST", "/logout", portal))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d %s", rec.Code, rec.Body.String())
	}
	if ok, _ := a.RequestIsAuthenticatedInSSO(nil, withCookie(a, "GET", "/", portal)); ok {
		t.Fatal("portal token still valid after logout")
	}
	if a.RequestIsAuthenticatedInHost(nil, withCookie(a, "GET", "/", site)) {
		t.Fatal("per host token still valid after logout")
	}
	// as with random ids: the portal session of another device is a different session
	if ok, _ := a.RequestIsAuthenticatedInSSO(nil, withCookie(a, "GET", "/", otherDevice)); !ok {
		t.Fatal("logout must not end the portal session of another device")
	}
	// a new login after the logout works
	time.Sleep(2 * time.Millisecond)
	if !a.RequestIsAuthenticatedInHost(nil, withCookie(a, "GET", "/", a.mintToken(tokenKindBrowser, "alice", exp, false))) {
		t.Fatal("session issued after the logout refused")
	}
	// the revocation survives a restart of the node
	a2 := &AuthRouter{Database: a.Database, Options: a.Options}
	a2.SetSharedSessionKey([]byte("k1-shared-key-material"))
	if ok, _ := a2.RequestIsAuthenticatedInSSO(nil, withCookie(a2, "GET", "/", portal)); ok {
		t.Fatal("revocation lost on restart")
	}
	// known limit: the logout is enforced by the node that handled it
	if ok, _ := b.RequestIsAuthenticatedInSSO(nil, withCookie(b, "GET", "/", portal)); !ok {
		t.Fatal("documented limit changed: update DEVELOPMENT.md (logout is per node)")
	}

	// log out all users: everything issued so far is refused, the cut-off is in the database
	rec = httptest.NewRecorder()
	b.HandleLogoutAllUsers(rec, httptest.NewRequest("POST", "/", nil))
	if ok, _ := b.RequestIsAuthenticatedInSSO(nil, withCookie(b, "GET", "/", otherDevice)); ok {
		t.Fatal("token still valid after log out all users")
	}
	var cut int64
	if err := b.Database.Read(DB_NAME, sessionsNotBeforeKey, &cut); err != nil || cut == 0 {
		t.Fatalf("cut-off not stored for the settings sync: %v", err)
	}
	// a node that receives the cut-off through the settings sync refuses the tokens after its restart
	a.Database.Write(DB_NAME, sessionsNotBeforeKey, cut)
	a3 := &AuthRouter{Database: a.Database, Options: a.Options}
	a3.SetSharedSessionKey([]byte("k1-shared-key-material"))
	if ok, _ := a3.RequestIsAuthenticatedInSSO(nil, withCookie(a3, "GET", "/", otherDevice)); ok {
		t.Fatal("synced cut-off not honoured")
	}
	time.Sleep(2 * time.Millisecond)
	if ok, _ := a3.RequestIsAuthenticatedInSSO(nil, withCookie(a3, "GET", "/", a3.mintToken(tokenKindGateway, "alice", exp, false))); !ok {
		t.Fatal("login after log out all users refused")
	}
}

// The router is reachable from the proxy status the admin UI reads as JSON:
// nothing added for HA may break marshalling it (a func field would).
func TestAuthRouterStaysMarshalable(t *testing.T) {
	a, _, _, _ := newSharedPair(t, "k1-shared-key-material", "k1-shared-key-material")
	a.UsersManagedElsewhere = func() bool { return true }
	out, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("AuthRouter no longer marshals: %v", err)
	}
	if strings.Contains(string(out), "k1-shared-key-material") {
		t.Fatal("the session key leaks into the status JSON")
	}
}

func TestSelfServiceRefusedWhenUsersAreSynced(t *testing.T) {
	a, ga, _, _ := newSharedPair(t, "k1-shared-key-material", "k1-shared-key-material")
	portal := a.mintToken(tokenKindGateway, "alice", time.Now().Add(time.Hour), false)
	call := func(path string) int {
		rec := httptest.NewRecorder()
		ga.handleUserPortalAPI(rec, withCookie(a, "POST", "/user/api/"+path, portal))
		return rec.Code
	}
	if call("2fa/disable") == http.StatusConflict {
		t.Fatal("self-service refused although the users are this node's own")
	}
	a.UsersManagedElsewhere = func() bool { return true }
	for _, path := range []string{"change-password", "2fa/setup", "2fa/enable", "2fa/disable", "passkey/register/begin", "passkey/register/complete", "passkey/remove"} {
		if c := call(path); c != http.StatusConflict {
			t.Errorf("%s on a node with synced users: want 409 got %d", path, c)
		}
	}
	if call("info") != http.StatusOK {
		t.Error("reading the profile must stay possible")
	}
}

// Logout records of signed tokens must not pile up on a long-running node:
// the once-a-minute housekeeping drops the ones no live token can match.
func TestSharedSessions_RevocationsArePrunedWhileRunning(t *testing.T) {
	a, _, _, _ := newSharedPair(t, "k1-shared-key-material", "k1-shared-key-material")
	now := time.Now()
	live := a.mintToken(tokenKindGateway, "alice", now.Add(time.Hour), false)
	a.revokeSessionToken(live, tokenKindGateway)
	a.revokeUserBrowserSessions("alice")
	a.shared.mu.Lock()
	a.shared.revoked["n:expired-token"] = now.Add(-time.Minute).Unix()
	a.shared.revoked["u:long-gone"] = now.Add(-30 * 24 * time.Hour).UnixMilli()
	a.saveRevocationsLocked()
	a.shared.mu.Unlock()

	a.minuteTick()

	a.shared.mu.Lock()
	left := len(a.shared.revoked)
	_, expired := a.shared.revoked["n:expired-token"]
	_, gone := a.shared.revoked["u:long-gone"]
	a.shared.mu.Unlock()
	if expired || gone || left != 2 {
		t.Fatalf("expired logout records kept or live ones dropped: %d left", left)
	}
	stored := map[string]int64{}
	a.Database.Read(DB_NAME, revocationsKey, &stored)
	if len(stored) != 2 {
		t.Fatalf("pruned records still in the database: %v", stored)
	}
	if _, ok := a.verifyToken(live, tokenKindGateway); ok {
		t.Fatal("a logged out token that has not expired must stay refused")
	}

	// without a shared key the housekeeping has nothing to do and must not fail
	plain, _ := newTestGateway(t)
	plain.minuteTick()
}
