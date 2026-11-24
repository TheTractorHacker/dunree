package forwardproxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/foleyit/dunree/mod/adminallow"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/foleyit/dunree/mod/database"
	"github.com/foleyit/dunree/mod/destguard"
	"github.com/foleyit/dunree/mod/forwardproxy/cproxy"
	"github.com/foleyit/dunree/mod/info/logger"
	"github.com/foleyit/dunree/mod/utils"
)

// ZrFilter decides which clients may use the forward proxy. The proxy listens on all interfaces, so by
// default only clients on this machine or on a private / link-local network (LAN, docker, VPN) are
// served. Handler.SetAllowPublicClients(true) restores the old behaviour of serving any source address.
// When a login is set (Handler.SetCredentials) every client must also send it as Proxy-Authorization
// basic auth; without a login the proxy stays unauthenticated as before.
type ZrFilter struct {
	h *Handler
}

// guardedDialer dials through the destination guard (mod/destguard). Without the opt-in restriction this is
// net.DialTimeout with the same 10 s as the default dialer, so behaviour is unchanged.
type guardedDialer struct {
	logger *logger.Logger
}

func (d guardedDialer) Dial(address string) cproxy.Socket {
	conn, err := destguard.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		if d.logger != nil {
			d.logger.PrintAndLog("Forward Proxy", "Unable to establish connection to ["+address+"]", err)
		}
		return nil
	}
	// The admin allow-list also protects the admin port from being reached through this proxy: check the
	// address that was actually dialled (after DNS), so names cannot be used to dodge it.
	if adminallow.DialBlocked("tcp", conn.RemoteAddr().String()) {
		conn.Close()
		if d.logger != nil {
			d.logger.PrintAndLog("Forward Proxy", "Refused connection to ["+address+"]: it is the admin listener", nil)
		}
		return nil
	}
	return conn
}

type Handler struct {
	server             *http.Server
	handler            *http.Handler
	running            bool
	allowPublicClients atomic.Bool
	credentials        atomic.Pointer[proxyLogin] //nil = no login required (the default)
	db                 *database.Database
	logger             *logger.Logger
	Port               int
}

func NewForwardProxy(sysdb *database.Database, port int, logger *logger.Logger) *Handler {
	h := &Handler{
		db:      sysdb,
		server:  nil,
		running: false,
		logger:  logger,
		Port:    port,
	}
	handler := cproxy.New(cproxy.Options.Filter(ZrFilter{h: h}), cproxy.Options.Dialer(guardedDialer{logger: logger}))
	h.handler = &handler
	if sysdb != nil {
		allowPublic := false
		sysdb.Read("fwdproxy", "allowPublicClients", &allowPublic)
		h.allowPublicClients.Store(allowPublic)
		login := proxyLogin{}
		sysdb.Read("fwdproxy", "login", &login)
		if login.Username != "" && login.Hash != "" {
			h.credentials.Store(&login)
		}
	}
	return h
}

// Timeouts of the proxy listener. They only cover reading the CONNECT request and idle keep-alive
// connections: an established tunnel is hijacked, which clears the deadlines, so tunnels are not cut.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

// proxyLogin is the optional login of the forward proxy. Only a hash of "username:password" is kept.
type proxyLogin struct {
	Username string
	Hash     string
}

func hashLogin(username, password string) string {
	sum := sha256.Sum256([]byte(username + ":" + password))
	return hex.EncodeToString(sum[:])
}

// SetCredentials makes the proxy require this login (Proxy-Authorization basic auth) from every
// client. An empty username removes the login again.
func (h *Handler) SetCredentials(username, password string) error {
	if username == "" {
		h.credentials.Store(nil)
		return nil
	}
	if strings.Contains(username, ":") {
		return errors.New("the username must not contain a colon")
	}
	if password == "" {
		return errors.New("the password must not be empty")
	}
	h.credentials.Store(&proxyLogin{Username: username, Hash: hashLogin(username, password)})
	return nil
}

// loginAccepted tells whether the request carries the configured login (always true when none is set)
func (h *Handler) loginAccepted(r *http.Request) bool {
	login := h.credentials.Load()
	if login == nil {
		return true
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashLogin(username, password)), []byte(login.Hash)) == 1
}

// SetAllowPublicClients chooses whether clients with a public source address may use the proxy
func (h *Handler) SetAllowPublicClients(allow bool) { h.allowPublicClients.Store(allow) }

// clientAllowed tells whether a client at remoteAddr (host:port) may use the proxy
func (h *Handler) clientAllowed(remoteAddr string) bool {
	if h.allowPublicClients.Load() {
		return true
	}
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap().WithZone("")
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnatPrefix.Contains(ip)
}

// cgnatPrefix is the shared address space (RFC 6598). Overlay VPNs such as Tailscale hand out
// addresses from it, so it counts as a private network here
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// Start the forward proxy
func (h *Handler) Start() error {
	if h.running {
		return errors.New("forward proxy already running")
	}
	server := &http.Server{
		Addr:              ":" + strconv.Itoa(h.Port),
		Handler:           *h.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	h.server = server

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err != nil {
				log.Println(err.Error())
			}
		}
	}()

	h.running = true
	if h.logger != nil {
		if h.allowPublicClients.Load() {
			h.logger.PrintAndLog("Forward Proxy", "Serving clients from any source address (public clients allowed)", nil)
		} else {
			h.logger.PrintAndLog("Forward Proxy", "Serving only clients on this machine or a private network; public source addresses are refused (POST allow=true to /api/tools/fwdproxy/publicclients restores the old behaviour)", nil)
		}
	}
	return nil
}

// Stop the forward proxy
func (h *Handler) Stop() error {
	if h.running && h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.server.Shutdown(ctx); err != nil {
			return err
		}
		h.running = false
		h.server = nil
	}
	return nil
}

// Update the port number of the forward proxy
func (h *Handler) UpdatePort(newPort int) error {
	if newPort < 1 || newPort > 65535 {
		return errors.New("Invalid port number: use a port between 1 and 65535")
	}
	if newPort != h.Port {
		//The listener starts in the background, so probe the port first or a conflict (for example
		//the management port) would be reported as success while nothing listens
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(newPort))
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return errors.New("Port " + strconv.Itoa(newPort) + " needs elevated permission, choose a port above 1024")
			}
			return errors.New("Port " + strconv.Itoa(newPort) + " is already in use by another program")
		}
		ln.Close()
	}
	h.Stop()
	h.Port = newPort
	return h.Start()
}

func (it ZrFilter) IsAuthorized(w http.ResponseWriter, r *http.Request) bool {
	if it.h == nil {
		return true
	}
	if !it.h.clientAllowed(r.RemoteAddr) {
		if it.h.logger != nil {
			it.h.logger.PrintAndLog("Forward Proxy", "Refused client "+r.RemoteAddr+": not on a private network (public clients are not allowed)", nil)
		}
		http.Error(w, "403 - Forbidden", http.StatusForbidden)
		return false
	}
	if !it.h.loginAccepted(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Forward Proxy"`)
		http.Error(w, "407 - Proxy Authentication Required", http.StatusProxyAuthRequired)
		return false
	}
	return true
}

// Handle the optional login of the proxy. GET reads it (never the password), POST username + password
// sets it, POST clear=true removes it
func (h *Handler) HandleCredentials(w http.ResponseWriter, r *http.Request) {
	clear, _ := utils.PostBool(r, "clear")
	username, err := utils.PostPara(r, "username")
	if err != nil && !clear {
		state := struct {
			Required bool
			Username string
		}{}
		if login := h.credentials.Load(); login != nil {
			state.Required, state.Username = true, login.Username
		}
		js, _ := json.Marshal(state)
		utils.SendJSONResponse(w, string(js))
		return
	}
	username = strings.TrimSpace(username)
	if clear {
		username = ""
	} else if username == "" {
		//A blank username must not silently remove the login: that is what clear=true is for
		utils.SendErrorResponse(w, "the username must not be empty (use clear=true to remove the login)")
		return
	}
	password, _ := utils.PostPara(r, "password")
	if err := h.SetCredentials(strings.TrimSpace(username), password); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	login := proxyLogin{}
	if l := h.credentials.Load(); l != nil {
		login = *l
	}
	if h.logger != nil {
		h.logger.PrintAndLog("Forward Proxy", "Login required: "+strconv.FormatBool(login.Username != ""), nil)
	}
	if h.db != nil {
		h.db.Write("fwdproxy", "login", login)
	}
	utils.SendOK(w)
}

// Handle the "serve clients with a public source address" setting. GET reads it, POST allow=true|false sets it
func (h *Handler) HandlePublicClients(w http.ResponseWriter, r *http.Request) {
	allow, err := utils.PostBool(r, "allow")
	if err != nil {
		js, _ := json.Marshal(h.allowPublicClients.Load())
		utils.SendJSONResponse(w, string(js))
		return
	}
	h.SetAllowPublicClients(allow)
	if h.logger != nil {
		h.logger.PrintAndLog("Forward Proxy", "Clients with a public source address allowed: "+strconv.FormatBool(allow), nil)
	}
	if h.db != nil {
		h.db.Write("fwdproxy", "allowPublicClients", allow)
	}
	utils.SendOK(w)
}

// Handle port change of the forward proxy
func (h *Handler) HandlePort(w http.ResponseWriter, r *http.Request) {
	port, err := utils.PostInt(r, "port")
	if err != nil {
		js, _ := json.Marshal(h.Port)
		utils.SendJSONResponse(w, string(js))
	} else {
		//Update the port
		err = h.UpdatePort(port)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		h.logger.PrintAndLog("Forward Proxy", "HTTP Forward Proxy port updated to :"+strconv.Itoa(h.Port), nil)
		h.db.Write("fwdproxy", "port", port)
		utils.SendOK(w)
	}
}

// Handle power toggle of the forward proxys
func (h *Handler) HandleToogle(w http.ResponseWriter, r *http.Request) {
	enabled, err := utils.PostBool(r, "enable")
	if err != nil {
		//Get the current state of the forward proxy
		js, _ := json.Marshal(h.running)
		utils.SendJSONResponse(w, string(js))
	} else {
		if enabled {
			err = h.Start()
			if err != nil {
				h.logger.PrintAndLog("Forward Proxy", "Unable to start forward proxy server", err)
				utils.SendErrorResponse(w, err.Error())
				return
			}
			h.logger.PrintAndLog("Forward Proxy", "HTTP Forward Proxy Started, listening on :"+strconv.Itoa(h.Port), nil)
		} else {
			err = h.Stop()
			if err != nil {
				h.logger.PrintAndLog("Forward Proxy", "Unable to stop forward proxy server", err)
				utils.SendErrorResponse(w, err.Error())
				return
			}
			h.logger.PrintAndLog("Forward Proxy", "HTTP Forward Proxy Stopped", nil)
		}
		h.db.Write("fwdproxy", "enabled", enabled)
		utils.SendOK(w)
	}
}
