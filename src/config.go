package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/loadbalance"
	"github.com/TheTractorHacker/dunree/mod/eventsystem"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
	"github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin/events"
	"github.com/TheTractorHacker/dunree/mod/tlscert"
	"github.com/TheTractorHacker/dunree/mod/utils"
)

/*
	Reverse Proxy Configs

	The following section handle
	the reverse proxy configs
*/

type Record struct {
	ProxyType               string
	Rootname                string
	ProxyTarget             string
	UseTLS                  bool
	BypassGlobalTLS         bool
	SkipTlsValidation       bool
	RequireBasicAuth        bool
	BasicAuthCredentials    []*dynamicproxy.BasicAuthCredentials
	BasicAuthExceptionRules []*dynamicproxy.BasicAuthExceptionRule
}

/*
Load Reverse Proxy Config from file and append it to current runtime proxy router
*/
func LoadReverseProxyConfig(configFilepath string) error {
	//Load the config file from disk
	endpointConfig, err := os.ReadFile(configFilepath)
	if err != nil {
		return err
	}

	//Parse it into dynamic proxy endpoint
	thisConfigEndpoint := dynamicproxy.GetDefaultProxyEndpoint()
	err = json.Unmarshal(endpointConfig, &thisConfigEndpoint)
	if err != nil {
		return err
	}

	//Make sure the tags are not nil
	if thisConfigEndpoint.Tags == nil {
		thisConfigEndpoint.Tags = []string{}
	}

	//Make sure the TLS options are not nil
	if thisConfigEndpoint.TlsOptions == nil {
		thisConfigEndpoint.TlsOptions = tlscert.GetDefaultHostSpecificTlsBehavior()
	}

	//Matching domain not set. Assume root
	if thisConfigEndpoint.RootOrMatchingDomain == "" {
		thisConfigEndpoint.RootOrMatchingDomain = "/"
	}

	switch thisConfigEndpoint.ProxyType {
	case dynamicproxy.ProxyTypeRoot:
		//This is a root config file
		rootProxyEndpoint, err := dynamicProxyRouter.PrepareProxyRoute(&thisConfigEndpoint)
		if err != nil {
			return err
		}

		dynamicProxyRouter.SetProxyRouteAsRoot(rootProxyEndpoint)

	case dynamicproxy.ProxyTypeHost:
		//This is a host config file
		readyProxyEndpoint, err := dynamicProxyRouter.PrepareProxyRoute(&thisConfigEndpoint)
		if err != nil {
			return err
		}

		dynamicProxyRouter.AddProxyRouteToRuntime(readyProxyEndpoint)
	default:
		return errors.New("not supported proxy type")
	}

	SystemWideLogger.PrintAndLog("proxy-config", thisConfigEndpoint.RootOrMatchingDomain+" -> "+loadbalance.GetUpstreamsAsString(thisConfigEndpoint.ActiveOrigins)+" routing rule loaded", nil)
	return nil
}

func filterProxyConfigFilename(filename string) string {
	//Filter out wildcard characters
	filename = strings.ReplaceAll(filename, "*", "(ST)")
	filename = strings.ReplaceAll(filename, "?", "(QM)")
	filename = strings.ReplaceAll(filename, "[", "(OB)")
	filename = strings.ReplaceAll(filename, "]", "(CB)")
	filename = strings.ReplaceAll(filename, "#", "(HT)")
	return filepath.ToSlash(filename)
}

// SaveReverseProxyConfig stores a proxy rule and tells the plugins that subscribed
// to it: proxyRuleAdded when the rule had no stored configuration before,
// proxyRuleEdited otherwise. Nothing is sent when the write failed.
func SaveReverseProxyConfig(endpoint *dynamicproxy.ProxyEndpoint) error {
	//One save or removal at a time: the "was it stored before" check, the write and
	//the hand-over of the event are one step, so two requests that store the same
	//new rule at the same moment give one proxyRuleAdded and one proxyRuleEdited
	proxyConfigFileLock.Lock()
	defer proxyConfigFileLock.Unlock()
	existed, err := saveReverseProxyConfigFile(endpoint)
	if err != nil {
		return err
	}
	info := events.ProxyRuleInfo{
		RootOrMatchingDomain: endpoint.RootOrMatchingDomain,
		MatchingDomainAlias:  append([]string{}, endpoint.MatchingDomainAlias...),
		IsRoot:               endpoint.ProxyType == dynamicproxy.ProxyTypeRoot,
		Disabled:             endpoint.Disabled,
		Tags:                 append([]string{}, endpoint.Tags...),
	}
	if existed {
		emitProxyRuleEvent(&events.ProxyRuleEditedEvent{ProxyRuleInfo: info})
	} else {
		emitProxyRuleEvent(&events.ProxyRuleAddedEvent{ProxyRuleInfo: info})
	}
	return nil
}

// proxyConfigFileLock is held while the config file of a proxy rule is written or
// removed and its event is handed to the event system (which sends it on its own
// goroutines: the lock does not wait for a plugin)
var proxyConfigFileLock sync.Mutex

// saveReverseProxyConfigQuietly stores a proxy rule without an event. For rewrites
// that are not a change by the administrator (a basic auth hash upgrade at login).
func saveReverseProxyConfigQuietly(endpoint *dynamicproxy.ProxyEndpoint) error {
	proxyConfigFileLock.Lock()
	defer proxyConfigFileLock.Unlock()
	_, err := saveReverseProxyConfigFile(endpoint)
	return err
}

// emitProxyRuleEvent sends a proxy rule event to its subscribers (none: nothing happens)
func emitProxyRuleEvent(payload events.EventPayload) {
	if eventsystem.Publisher == nil {
		return //event system not started (early start, tests)
	}
	eventsystem.Publisher.Emit(payload)
}

// saveReverseProxyConfigFile writes the config file of a proxy rule and reports
// whether the rule had a config file before
func saveReverseProxyConfigFile(endpoint *dynamicproxy.ProxyEndpoint) (existed bool, err error) {
	//Get filename for saving
	filename := filepath.Join(CONF_HTTP_PROXY, endpoint.RootOrMatchingDomain+".config")
	if endpoint.ProxyType == dynamicproxy.ProxyTypeRoot {
		filename = filepath.Join(CONF_HTTP_PROXY, "root.config")
	}

	filename = filterProxyConfigFilename(filename)

	//Save config to file
	js, err := json.MarshalIndent(endpoint, "", " ")
	if err != nil {
		return false, err
	}

	existed = utils.FileExists(filename)
	return existed, os.WriteFile(filename, js, 0775)
}

func RemoveReverseProxyConfig(endpoint string) error {
	filename := filepath.Join(CONF_HTTP_PROXY, endpoint+".config")
	if endpoint == "/" {
		filename = filepath.Join(CONF_HTTP_PROXY, "/root.config")
	}

	filename = filterProxyConfigFilename(filename)

	proxyConfigFileLock.Lock()
	defer proxyConfigFileLock.Unlock()
	if !utils.FileExists(filename) {
		return errors.New("target endpoint not exists")
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	emitProxyRuleEvent(&events.ProxyRuleRemovedEvent{RootOrMatchingDomain: endpoint, IsRoot: endpoint == "/"})
	return nil
}

// Get the default root config that point to the internal static web server
// this will be used if root config is not found (new deployment / missing root.config file)
func GetDefaultRootConfig() (*dynamicproxy.ProxyEndpoint, error) {
	//Get the default proxy endpoint
	rootProxyEndpointConfig := dynamicproxy.GetDefaultProxyEndpoint()
	rootProxyEndpointConfig.ProxyType = dynamicproxy.ProxyTypeRoot
	rootProxyEndpointConfig.RootOrMatchingDomain = "/"
	rootProxyEndpointConfig.ActiveOrigins = []*loadbalance.Upstream{
		{
			OriginIpOrDomain:    "127.0.0.1:" + staticWebServer.GetListeningPort(),
			RequireTLS:          false,
			SkipCertValidations: false,
			Weight:              0,
		},
	}
	rootProxyEndpointConfig.DefaultSiteOption = dynamicproxy.DefaultSite_InternalStaticWebServer
	rootProxyEndpointConfig.DefaultSiteValue = ""

	//Default settings
	rootProxyEndpoint, err := dynamicProxyRouter.PrepareProxyRoute(&rootProxyEndpointConfig)
	if err != nil {
		return nil, err
	}

	return rootProxyEndpoint, nil
}

/*
	Importer and Exporter of Dunree proxy config
*/

func handleLoggerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		logger.HandleGetLogConfig(CONF_LOG_CONFIG)(w, r)
	case http.MethodPost:
		logger.HandleUpdateLogConfig(CONF_LOG_CONFIG, SystemWideLogger)(w, r)
	default:
		utils.SendErrorResponse(w, "Method not allowed")
	}
}
