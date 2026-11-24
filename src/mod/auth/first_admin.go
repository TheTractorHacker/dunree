package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	First admin registration guard

	While the auth database holds no account, /api/auth/register creates the root admin. The admin
	listener is on all interfaces by default, so without a guard whoever reaches the port first owns
	the install. The guard accepts that registration only
	  - from the machine itself (loopback, not relayed by a proxy), or
	  - with the one-time setup token that is printed to the console / log at startup.
	AllowRemote restores the old behaviour (anyone, no token).

	The mutex is held across the "no account yet" check and the create, so two concurrent requests
	cannot both create an admin.
*/

// SetupTokenHeader carries the setup token as an alternative to the setup_token form field
const SetupTokenHeader = "X-Setup-Token"

type FirstAdminGuard struct {
	agent       *AuthAgent
	allowRemote bool

	mu        sync.Mutex
	token     string
	announced bool
}

// NewFirstAdminGuard returns the guard of the first admin registration.
// allowRemote = true keeps the pre-guard behaviour: any client may create the first account
func (a *AuthAgent) NewFirstAdminGuard(allowRemote bool) *FirstAdminGuard {
	return &FirstAdminGuard{agent: a, allowRemote: allowRemote}
}

func newSetupToken() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic("auth: no random source for the setup token: " + err.Error())
	}
	s := hex.EncodeToString(b)
	return s[0:5] + "-" + s[5:10] + "-" + s[10:15] + "-" + s[15:20]
}

// announce prints the token once. The caller holds g.mu
func (g *FirstAdminGuard) announce() {
	if g.token == "" {
		g.token = newSetupToken()
	}
	if g.announced {
		return
	}
	g.announced = true
	g.agent.Logger.PrintAndLog("auth", "No admin account exists yet. Create it from this machine, or from another machine with this one-time setup token: "+g.token, nil)
}

// Announce prints the setup token when no account exists and a token is needed. Call it at startup
func (g *FirstAdminGuard) Announce() {
	if g.allowRemote || g.agent.GetUserCounts() != 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.announce()
}

// isDirectLoopback tells whether the request was sent by this machine itself. A request relayed by a
// reverse proxy on this machine also arrives from loopback, so any forwarding header disqualifies it.
// The headers can only remove the exemption, never grant it, so trusting them here is safe.
func isDirectLoopback(r *http.Request) bool {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded", "Cf-Connecting-Ip", "True-Client-Ip", "Via"} {
		if len(r.Header.Values(h)) > 0 {
			return false
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TokenRequired tells whether this request needs the setup token to create the first admin
func (g *FirstAdminGuard) TokenRequired(r *http.Request) bool {
	if g.allowRemote || isDirectLoopback(r) {
		return false
	}
	return g.agent.GetUserCounts() == 0
}

// HandleRegister creates the root admin while no account exists. Require POST username, password
// and, unless the request comes from this machine, setup_token (or the X-Setup-Token header).
func (g *FirstAdminGuard) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "405 - Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.agent.GetUserCounts() != 0 {
		//This function is disabled
		utils.SendErrorResponse(w, "Root management account already exists")
		return
	}

	if !g.allowRemote && !isDirectLoopback(r) {
		g.announce()
		given := r.Header.Get(SetupTokenHeader)
		if given == "" {
			given, _ = utils.PostPara(r, "setup_token")
		}
		given = strings.ToLower(strings.TrimSpace(given))
		if subtle.ConstantTimeCompare([]byte(given), []byte(g.token)) != 1 {
			g.agent.Logger.PrintAndLog("auth", "Refused first admin registration from "+r.RemoteAddr+": setup token missing or wrong", nil)
			utils.SendErrorResponse(w, "Setup token required. It is printed in the server console / log at startup. Enter it, or create the account from the server itself.")
			return
		}
	}

	//Allow register root admin
	g.agent.HandleRegisterWithoutEmail(w, r, func(username, reserved string) {})
}
