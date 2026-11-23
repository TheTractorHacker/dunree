package main

/*
	errorpagesapi.go

	Admin APIs of the customisable error pages (mod/errorpages; the request side is
	mod/dynamicproxy/errorpages_hook.go). Everything is off until the owner saves a customisation and
	switches it on: with nothing saved every answer of the proxy is the one it always gave.

	GET  /api/errorpages/classes                      page classes, template variables, starter templates, limits
	GET  /api/errorpages/get                          the saved customisation (theme, pages, per host pages)
	POST /api/errorpages/save      host, pages (JSON {class: {Title, Message, Template}}), [enabled], [theme (JSON)]
	                                                  replaces the pages of one scope (host empty = all sites) and,
	                                                  when given, the master switch and the theme. One request per Save.
	POST /api/errorpages/theme     enabled, theme (JSON)             master switch and theme only
	POST /api/errorpages/template/set     class, [host], title, message, template    one page
	POST /api/errorpages/template/delete  class, [host]              back to the built-in page (class empty + host: the whole host)
	POST /api/errorpages/preview   class, [host], [page (JSON)], [theme (JSON)] -> {"html": "..."}  sample values, saves nothing
	POST /api/errorpages/reset                        removes every customisation
	GET  /api/errorpages/test?class=403[&host=...]    the page a visitor gets now, with its status code and headers

	State: <conf>/errorpages.json. Changes are in the security audit log (errorpages.*) and the change history.
*/

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/errorpages"
	"imuslab.com/zoraxy/mod/utils"
)

var errorPageMgr *errorpages.Manager

// initErrorPages loads <conf>/errorpages.json and hands the manager to the proxy. Without that file
// (the default) the manager is inactive and nothing about the proxy changes.
func initErrorPages() {
	errorPageMgr = errorpages.NewManager(filepath.Join(CONF_FOLDER, errorpages.FileName), func(msg string) {
		if SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("errorpages", msg, nil)
		}
	})
	dynamicproxy.SetCustomErrorPages(errorPageMgr)
}

func RegisterErrorPageAPIs(authRouter *auth.RouterDef) {
	if errorPageMgr == nil {
		initErrorPages()
	}
	authRouter.HandleFunc("/api/errorpages/classes", HandleErrorPageClasses)
	authRouter.HandleFunc("/api/errorpages/get", HandleErrorPagesGet)
	authRouter.HandleFunc("/api/errorpages/save", HandleErrorPagesSave)
	authRouter.HandleFunc("/api/errorpages/theme", HandleErrorPagesTheme)
	authRouter.HandleFunc("/api/errorpages/template/set", HandleErrorPageTemplateSet)
	authRouter.HandleFunc("/api/errorpages/template/delete", HandleErrorPageTemplateDelete)
	authRouter.HandleFunc("/api/errorpages/preview", HandleErrorPagePreview)
	authRouter.HandleFunc("/api/errorpages/reset", HandleErrorPagesReset)
	authRouter.HandleFunc("/api/errorpages/test", HandleErrorPageTest)
}

func errorPagesJSON(w http.ResponseWriter, v interface{}) {
	js, _ := json.Marshal(v)
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}

func errorPagesMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func HandleErrorPageClasses(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodGet) {
		return
	}
	errorPagesJSON(w, map[string]interface{}{
		"classes":   errorpages.Classes(),
		"variables": errorpages.Variables(),
		"starters":  errorpages.Starters(),
		"limits": map[string]int{"templateBytes": errorpages.MaxTemplateBytes, "renderedBytes": errorpages.MaxRenderedBytes,
			"textLength": errorpages.MaxTextLen, "hosts": errorpages.MaxHosts},
		"csp": errorpages.ContentSecurityPolicy,
	})
}

type errorPagesView struct {
	*errorpages.Config
	Active bool //the master switch is on: customised classes are served
}

func HandleErrorPagesGet(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodGet) {
		return
	}
	errorPagesJSON(w, errorPagesView{Config: errorPageMgr.Get(), Active: errorPageMgr.Active()})
}

// errorPagesHostParam reads the optional host of a request ("" = all sites)
func errorPagesHostParam(r *http.Request) string {
	h, _ := utils.PostPara(r, "host")
	return errorpages.NormalizeHost(h)
}

func errorPagesParseTheme(raw string) (*errorpages.Theme, error) {
	th := &errorpages.Theme{}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(th); err != nil {
		return nil, err
	}
	return th, nil
}

// errorPagesApplyMeta applies the optional "enabled" and "theme" fields of a request to cfg
func errorPagesApplyMeta(r *http.Request, cfg *errorpages.Config) error {
	if raw, err := utils.PostPara(r, "enabled"); err == nil {
		cfg.Enabled = raw == "true" || raw == "1" || raw == "on"
	}
	if raw, err := utils.PostPara(r, "theme"); err == nil {
		th, err := errorPagesParseTheme(raw)
		if err != nil {
			return err
		}
		cfg.Theme = *th
	}
	return nil
}

func HandleErrorPagesSave(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodPost) {
		return
	}
	cfg := errorPageMgr.Get()
	host := errorPagesHostParam(r)
	if raw, err := utils.PostPara(r, "pages"); err == nil {
		pages := map[errorpages.Class]*errorpages.Page{}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&pages); err != nil {
			utils.SendErrorResponse(w, "Invalid pages: "+err.Error())
			return
		}
		if host == "" {
			cfg.Pages = pages
		} else {
			cfg.Hosts[host] = pages
		}
	}
	if err := errorPagesApplyMeta(r, cfg); err != nil {
		utils.SendErrorResponse(w, "Invalid theme: "+err.Error())
		return
	}
	if err := errorPageMgr.Set(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleErrorPagesTheme(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodPost) {
		return
	}
	cfg := errorPageMgr.Get()
	if err := errorPagesApplyMeta(r, cfg); err != nil {
		utils.SendErrorResponse(w, "Invalid theme: "+err.Error())
		return
	}
	if err := errorPageMgr.Set(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleErrorPageTemplateSet(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodPost) {
		return
	}
	class, err := utils.PostPara(r, "class")
	if err != nil {
		utils.SendErrorResponse(w, "class not given")
		return
	}
	page := &errorpages.Page{}
	page.Title, _ = utils.PostPara(r, "title")
	page.Message, _ = utils.PostPara(r, "message")
	page.Template, _ = utils.PostPara(r, "template")
	cfg := errorPageMgr.Get()
	if host := errorPagesHostParam(r); host == "" {
		cfg.Pages[errorpages.Class(class)] = page
	} else {
		if cfg.Hosts[host] == nil {
			cfg.Hosts[host] = map[errorpages.Class]*errorpages.Page{}
		}
		cfg.Hosts[host][errorpages.Class(class)] = page
	}
	if err := errorPageMgr.Set(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleErrorPageTemplateDelete(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodPost) {
		return
	}
	class, _ := utils.PostPara(r, "class")
	host := errorPagesHostParam(r)
	cfg := errorPageMgr.Get()
	switch {
	case host == "" && class == "":
		utils.SendErrorResponse(w, "class not given")
		return
	case host == "":
		delete(cfg.Pages, errorpages.Class(class))
	case class == "":
		delete(cfg.Hosts, host)
	default:
		delete(cfg.Hosts[host], errorpages.Class(class))
	}
	if err := errorPageMgr.Set(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleErrorPagePreview(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodPost) {
		return
	}
	class, _ := utils.PostPara(r, "class")
	pr := errorpages.PreviewRequest{Class: errorpages.Class(class)}
	pr.Host, _ = utils.PostPara(r, "host")
	if raw, err := utils.PostPara(r, "page"); err == nil {
		pr.Page = &errorpages.Page{}
		if err := json.Unmarshal([]byte(raw), pr.Page); err != nil {
			utils.SendErrorResponse(w, "Invalid page: "+err.Error())
			return
		}
	}
	if raw, err := utils.PostPara(r, "theme"); err == nil {
		th, err := errorPagesParseTheme(raw)
		if err != nil {
			utils.SendErrorResponse(w, "Invalid theme: "+err.Error())
			return
		}
		pr.Theme = th
	}
	out, err := errorPageMgr.Preview(pr)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	errorPagesJSON(w, map[string]string{"html": out})
}

func HandleErrorPagesReset(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodPost) {
		return
	}
	if err := errorPageMgr.Reset(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleErrorPageTest answers like the proxy answers a visitor right now: the customised page with its
// headers when the class is customised (and switched on), else the built-in page. Nothing is logged as blocked.
func HandleErrorPageTest(w http.ResponseWriter, r *http.Request) {
	if !errorPagesMethod(w, r, http.MethodGet) {
		return
	}
	class, _ := utils.GetPara(r, "class")
	var info *errorpages.ClassInfo
	for _, ci := range errorpages.Classes() {
		if string(ci.ID) == class {
			c := ci
			info = &c
		}
	}
	if info == nil {
		http.Error(w, "400 - unknown page", http.StatusBadRequest)
		return
	}
	host, _ := utils.GetPara(r, "host")
	if host = errorpages.NormalizeHost(host); host == "" || strings.HasPrefix(host, "*.") {
		host = "app.example.com"
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	w.Header().Set("X-Robots-Tag", "noindex")
	if body, ok := errorPageMgr.Render(errorpages.Request{Class: info.ID, Status: info.SampleStatus, Host: host, RequestID: "ZX-TEST-TEST", ClientIP: clientIP}); ok {
		w.Header().Set("X-Zoraxy-Error-Page", "custom")
		errorpages.SetHeaders(w.Header(), len(body))
		w.WriteHeader(info.SampleStatus)
		w.Write(body)
		return
	}
	w.Header().Set("X-Zoraxy-Error-Page", "built-in")
	w.Header().Set("Cache-Control", "no-store")
	body, html := dynamicproxy.BuiltinErrorPage(info.ID)
	if html {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if len(body) == 0 {
			body = []byte("(The built-in answer for this page has no content: the visitor only gets the status " + info.Statuses + ".)\n")
		}
	}
	w.WriteHeader(info.SampleStatus)
	w.Write(body)
}
