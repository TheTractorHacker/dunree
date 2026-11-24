package zorxauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/*
	Shared (stateless) sessions for high availability, fork issue #81

	By default ZorxAuth sessions are random ids kept in memory and in the node's
	database, so only the node that issued a session knows it. With a shared
	session key (derived from the cluster secret, see SetSharedSessionKey) the
	portal cookie, the per host cookie and the one-time validation code become
	HMAC signed tokens that carry the user name and the expiry. Any node holding
	the same key accepts them, and they survive a restart without the database.

	Without a key nothing here is used and tokens stay random ids exactly as
	before. Sessions issued before the key was set keep working on their node.

	Revocation of signed tokens (they cannot simply be forgotten):
	  - logout: the portal token is revoked by its id and the user's per host
	    tokens issued before the logout are refused (this node only),
	  - "log out all users": a cut-off time stored in the database under
	    DB_NAME / sessionsNotBeforeKey, which the cluster settings sync carries
	    from the primary to the followers,
	  - a deleted user is refused everywhere the user list is synced to.
*/

const (
	sharedTokenPrefix = "zxs1."

	tokenKindGateway = "g" //SSO portal cookie
	tokenKindBrowser = "b" //cookie on a protected host
	tokenKindCode    = "c" //one-time validation code of the session-set redirect

	validationCodeLifetime = 30 * time.Second

	sessionsNotBeforeKey = "sessions_not_before" //DB_NAME: unix ms, signed tokens issued at or before it are refused
	revocationsKey       = "session_revocations" //DB_NAME: node local revocations of signed tokens
)

type tokenClaims struct {
	Kind       string `json:"k"`
	Username   string `json:"u"`
	Expiry     int64  `json:"e"` //unix seconds
	IssuedAt   int64  `json:"i"` //unix milliseconds
	RememberMe bool   `json:"r,omitempty"`
	Nonce      string `json:"n"`
}

// sharedSessions is the state of the signed token mode. The zero value means
// "off" (no key).
type sharedSessions struct {
	key       []byte
	notBefore atomic.Int64 //unix ms, all kinds

	mu      sync.Mutex
	revoked map[string]int64 //"n:<nonce>" -> token expiry (unix s), "u:<username>" -> cut-off (unix ms) for per host tokens and codes
	used    sync.Map         //nonce of a consumed validation code -> struct{}
}

// SetSharedSessionKey switches this router to signed session tokens that every
// node holding the same key accepts. Call it once, right after NewAuthRouter and
// before requests are served. An empty key leaves the default (random ids kept
// per node) in place.
func (ar *AuthRouter) SetSharedSessionKey(key []byte) {
	if len(key) == 0 {
		return
	}
	ar.shared.key = append([]byte{}, key...)
	ar.shared.revoked = map[string]int64{}
	if ar.Database != nil {
		var nb int64
		if ar.Database.KeyExists(DB_NAME, sessionsNotBeforeKey) && ar.Database.Read(DB_NAME, sessionsNotBeforeKey, &nb) == nil {
			ar.shared.notBefore.Store(nb)
		}
		stored := map[string]int64{}
		if ar.Database.KeyExists(DB_NAME, revocationsKey) && ar.Database.Read(DB_NAME, revocationsKey, &stored) == nil {
			ar.shared.revoked = stored
		}
	}
	ar.pruneRevocations()
}

// SharedSessionsEnabled reports whether sessions are signed tokens that other
// nodes with the same key accept.
func (ar *AuthRouter) SharedSessionsEnabled() bool { return len(ar.shared.key) > 0 }

func (ar *AuthRouter) signToken(body string) string {
	m := hmac.New(sha256.New, ar.shared.key)
	m.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func randomNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))
	}
	return hex.EncodeToString(buf)
}

// issueSessionToken returns the cookie value of a new session: a signed token
// in shared mode, the random id of generateSessionToken otherwise.
func (ar *AuthRouter) issueSessionToken(kind, username string, expiry time.Time, rememberMe bool) string {
	if !ar.SharedSessionsEnabled() {
		return ar.generateSessionToken()
	}
	return ar.mintToken(kind, username, expiry, rememberMe)
}

func (ar *AuthRouter) mintToken(kind, username string, expiry time.Time, rememberMe bool) string {
	raw, _ := json.Marshal(tokenClaims{
		Kind: kind, Username: username, Expiry: expiry.Unix(), IssuedAt: time.Now().UnixMilli(),
		RememberMe: rememberMe, Nonce: randomNonce(),
	})
	body := sharedTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + ar.signToken(body)
}

func isSharedToken(token string) bool { return strings.HasPrefix(token, sharedTokenPrefix) }

// verifyToken checks signature, kind, expiry and revocation of a signed token.
func (ar *AuthRouter) verifyToken(token, kind string) (*tokenClaims, bool) {
	if !ar.SharedSessionsEnabled() || !isSharedToken(token) {
		return nil, false
	}
	dot := strings.LastIndexByte(token, '.')
	if dot <= len(sharedTokenPrefix) {
		return nil, false
	}
	body, sig := token[:dot], token[dot+1:]
	if !hmac.Equal([]byte(ar.signToken(body)), []byte(sig)) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body[len(sharedTokenPrefix):])
	if err != nil {
		return nil, false
	}
	var c tokenClaims
	if json.Unmarshal(raw, &c) != nil || c.Kind != kind || c.Username == "" || c.Nonce == "" {
		return nil, false
	}
	if time.Now().Unix() >= c.Expiry {
		return nil, false
	}
	if c.IssuedAt <= ar.shared.notBefore.Load() {
		return nil, false
	}
	ar.shared.mu.Lock()
	_, tokenRevoked := ar.shared.revoked["n:"+c.Nonce]
	userCut, hasUserCut := ar.shared.revoked["u:"+c.Username]
	ar.shared.mu.Unlock()
	if tokenRevoked {
		return nil, false
	}
	if hasUserCut && kind != tokenKindGateway && c.IssuedAt <= userCut {
		return nil, false
	}
	return &c, true
}

// loadGatewaySession resolves an SSO portal cookie value. Random ids are looked
// up in the node's store as before; signed tokens are verified and need no
// store entry, so a session issued by another node is accepted.
func (ar *AuthRouter) loadGatewaySession(token string) (*GatewaySession, bool) {
	var claims *tokenClaims
	if isSharedToken(token) {
		c, ok := ar.verifyToken(token, tokenKindGateway)
		if !ok {
			return nil, false
		}
		claims = c
	}
	if v, ok := ar.gatewaySessionStore.Load(token); ok {
		if gs, ok := v.(*GatewaySession); ok {
			return gs, true
		}
		return nil, false
	}
	if claims == nil {
		return nil, false
	}
	return &GatewaySession{Username: claims.Username, Expiry: time.Unix(claims.Expiry, 0), RememberMe: claims.RememberMe}, true
}

// loadBrowserSession is loadGatewaySession for the cookie of a protected host.
func (ar *AuthRouter) loadBrowserSession(token string) (*BrowserSession, bool) {
	var claims *tokenClaims
	if isSharedToken(token) {
		c, ok := ar.verifyToken(token, tokenKindBrowser)
		if !ok {
			return nil, false
		}
		claims = c
	}
	if v, ok := ar.cookieIdStore.Load(token); ok {
		if bs, ok := v.(*BrowserSession); ok {
			return bs, true
		}
		return nil, false
	}
	if claims == nil {
		return nil, false
	}
	return &BrowserSession{Username: claims.Username, Expiry: time.Unix(claims.Expiry, 0)}, true
}

// consumeValidationCode resolves a one-time validation code to its user name
// and uses it up. A signed code issued by another node is accepted once per node.
func (ar *AuthRouter) consumeValidationCode(code string) (string, bool) {
	if isSharedToken(code) {
		c, ok := ar.verifyToken(code, tokenKindCode)
		if !ok {
			return "", false
		}
		if _, replay := ar.shared.used.LoadOrStore(c.Nonce, struct{}{}); replay {
			return "", false
		}
		nonce := c.Nonce
		time.AfterFunc(2*validationCodeLifetime, func() { ar.shared.used.Delete(nonce) })
		username := c.Username
		if v, ok := ar.sessionIdStore.LoadAndDelete(code); ok {
			//issued by this node: the store follows user renames and deletions
			if s, ok := v.(string); ok && s != "" {
				username = s
			}
		}
		return username, true
	}
	v, ok := ar.sessionIdStore.LoadAndDelete(code)
	if !ok {
		return "", false
	}
	username, ok := v.(string)
	return username, ok && username != ""
}

func (ar *AuthRouter) saveRevocationsLocked() {
	if ar.Database != nil {
		ar.Database.Write(DB_NAME, revocationsKey, ar.shared.revoked)
	}
}

// pruneRevocations drops entries that can no longer match a live token.
func (ar *AuthRouter) pruneRevocations() {
	longest := int64(getDefaultOptions().CookieDurationRememberMe)
	if ar.Options != nil {
		if d := int64(ar.Options.CookieDuration); d > longest {
			longest = d
		}
		if d := int64(ar.Options.CookieDurationRememberMe); d > longest {
			longest = d
		}
	}
	now := time.Now()
	ar.shared.mu.Lock()
	defer ar.shared.mu.Unlock()
	changed := false
	for k, v := range ar.shared.revoked {
		expired := false
		if strings.HasPrefix(k, "n:") {
			expired = v < now.Unix()
		} else {
			expired = v/1000+longest < now.Unix()
		}
		if expired {
			delete(ar.shared.revoked, k)
			changed = true
		}
	}
	if changed {
		ar.saveRevocationsLocked()
	}
}

// revokeSessionToken makes this node refuse one signed token (logout). Random
// ids need nothing here: deleting them from the store is enough.
func (ar *AuthRouter) revokeSessionToken(token, kind string) {
	c, ok := ar.verifyToken(token, kind)
	if !ok {
		return
	}
	ar.shared.mu.Lock()
	ar.shared.revoked["n:"+c.Nonce] = c.Expiry
	ar.saveRevocationsLocked()
	ar.shared.mu.Unlock()
}

// revokeUserBrowserSessions makes this node refuse the per host tokens and
// validation codes of a user that were issued up to now.
func (ar *AuthRouter) revokeUserBrowserSessions(username string) {
	if !ar.SharedSessionsEnabled() || username == "" {
		return
	}
	ar.shared.mu.Lock()
	ar.shared.revoked["u:"+username] = time.Now().UnixMilli()
	ar.saveRevocationsLocked()
	ar.shared.mu.Unlock()
}

// revokeAllSharedSessions refuses every signed token issued up to now. The
// cut-off is stored in the database, where the cluster settings sync picks it up.
func (ar *AuthRouter) revokeAllSharedSessions() {
	if !ar.SharedSessionsEnabled() {
		return
	}
	now := time.Now().UnixMilli()
	ar.shared.notBefore.Store(now)
	if ar.Database != nil {
		ar.Database.Write(DB_NAME, sessionsNotBeforeKey, now)
	}
}
