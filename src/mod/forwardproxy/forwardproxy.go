package forwardproxy

import (
	"context"
	"encoding/json"
	"errors"
	"imuslab.com/zoraxy/mod/adminallow"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/destguard"
	"imuslab.com/zoraxy/mod/forwardproxy/cproxy"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/utils"
)

type ZrFilter struct {
	//To be implemented
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
	server  *http.Server
	handler *http.Handler
	running bool
	db      *database.Database
	logger  *logger.Logger
	Port    int
}

func NewForwardProxy(sysdb *database.Database, port int, logger *logger.Logger) *Handler {
	thisFilter := ZrFilter{}
	handler := cproxy.New(cproxy.Options.Filter(thisFilter), cproxy.Options.Dialer(guardedDialer{logger: logger}))

	return &Handler{
		db:      sysdb,
		server:  nil,
		handler: &handler,
		running: false,
		logger:  logger,
		Port:    port,
	}
}

// Start the forward proxy
func (h *Handler) Start() error {
	if h.running {
		return errors.New("forward proxy already running")
	}
	server := &http.Server{Addr: ":" + strconv.Itoa(h.Port), Handler: *h.handler}
	h.server = server

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err != nil {
				log.Println(err.Error())
			}
		}
	}()

	h.running = true
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
	return true
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
