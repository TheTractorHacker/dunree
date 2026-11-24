package main

/*
	Vdir.go

	This script handle virtual directory functions
	in global scopes

	Author: tobychui
*/

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/utils"
)

// validateVdirH2C refuses h2c together with TLS: h2c is HTTP/2 over a plain TCP connection,
// a TLS target negotiates HTTP/2 by itself. Saying so beats storing a flag that does nothing.
func validateVdirH2C(useH2C bool, reqTLS bool, domain string) error {
	if !useH2C {
		return nil
	}
	if reqTLS || strings.HasPrefix(strings.ToLower(strings.TrimSpace(domain)), "https://") {
		return errors.New("h2c is HTTP/2 without TLS: switch off TLS for this target or leave h2c off")
	}
	return nil
}

// parseVdirH2C reads the h2c parameter. given is false when the request does not carry it
// (missing or empty). A value that is neither true nor false is refused: reading "1" or "on"
// as off would leave a script author believing the opt-in took.
func parseVdirH2C(r *http.Request) (useH2C bool, given bool, err error) {
	if raw, perr := utils.PostPara(r, "h2c"); perr != nil || strings.TrimSpace(raw) == "" {
		return false, false, nil
	}
	useH2C, err = utils.PostBool(r, "h2c")
	if err != nil {
		return false, true, errors.New("h2c must be true or false")
	}
	return useH2C, true, nil
}

// List the Virtual directory under given proxy rule
func ReverseProxyListVdir(w http.ResponseWriter, r *http.Request) {
	eptype, err := utils.ReadPara(r, "type") //Support root and host
	if err != nil {
		utils.SendErrorResponse(w, "type not defined")
		return
	}

	var targetEndpoint *dynamicproxy.ProxyEndpoint
	if eptype == "host" {
		endpoint, err := utils.ReadPara(r, "ep")
		if err != nil {
			utils.SendErrorResponse(w, "endpoint not defined")
			return
		}

		targetEndpoint, err = dynamicProxyRouter.LoadProxy(endpoint)
		if err != nil {
			utils.SendErrorResponse(w, "target endpoint not found")
			return
		}
	} else if eptype == "root" {
		targetEndpoint = dynamicProxyRouter.Root
	} else {
		utils.SendErrorResponse(w, "invalid type given")
		return
	}

	//Parse result to json
	vdirs := targetEndpoint.VirtualDirectories
	if targetEndpoint.VirtualDirectories == nil {
		//Avoid returning null to front-end
		vdirs = []*dynamicproxy.VirtualDirectoryEndpoint{}
	}
	js, _ := json.Marshal(vdirs)
	utils.SendJSONResponse(w, string(js))
}

// Add Virtual Directory to a host
func ReverseProxyAddVdir(w http.ResponseWriter, r *http.Request) {
	eptype, err := utils.PostPara(r, "type") //Support root and host
	if err != nil {
		utils.SendErrorResponse(w, "type not defined")
		return
	}

	matchingPath, err := utils.PostPara(r, "path")
	if err != nil {
		utils.SendErrorResponse(w, "matching path not defined")
		return
	}

	//Must start with /
	if !strings.HasPrefix(matchingPath, "/") {
		matchingPath = "/" + matchingPath
	}

	if len(matchingPath) > 200 || strings.ContainsAny(matchingPath, " \t\r\n\x00") {
		utils.SendErrorResponse(w, "the matching path cannot contain spaces and is limited to 200 characters")
		return
	}

	domain, err := utils.PostPara(r, "domain")
	if err != nil {
		utils.SendErrorResponse(w, "target domain not defined")
		return
	}
	domain = strings.TrimSpace(domain)
	if err := validateDefaultSiteTarget(1, domain); err != nil {
		utils.SendErrorResponse(w, "the target is not a valid host or host:port")
		return
	}

	reqTLSForGuard, _ := utils.PostBool(r, "reqTLS")
	if err := validateBackendTarget(domain, reqTLSForGuard); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Assume false if not given
	reqTLS, _ := utils.PostBool(r, "reqTLS")
	skipValid, _ := utils.PostBool(r, "skipValid")

	//h2c (HTTP/2 without TLS, for gRPC targets): off unless asked for
	useH2C, _, err := parseVdirH2C(r)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := validateVdirH2C(useH2C, reqTLS, domain); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Load the target proxy endpoint from runtime
	var targetProxyEndpoint *dynamicproxy.ProxyEndpoint
	if eptype == "root" {
		//Check if root is running at reverse proxy mode
		if dynamicProxyRouter.Root.DefaultSiteOption != dynamicproxy.DefaultSite_ReverseProxy {
			utils.SendErrorResponse(w, "virtual directory can only be added to root router under proxy mode")
			return
		}
		targetProxyEndpoint = dynamicProxyRouter.Root
	} else if eptype == "host" {
		endpointID, err := utils.PostPara(r, "endpoint")
		if err != nil {
			utils.SendErrorResponse(w, "endpoint not defined")
			return
		}

		loadedEndpoint, err := dynamicProxyRouter.LoadProxy(endpointID)
		if err != nil {
			utils.SendErrorResponse(w, "selected proxy host not exists")
			return
		}

		targetProxyEndpoint = loadedEndpoint
	} else {
		utils.SendErrorResponse(w, "invalid proxy type given")
		return
	}

	// Create a virtual directory entry base on the above info
	newVirtualDirectoryRouter := dynamicproxy.VirtualDirectoryEndpoint{
		MatchingPath:        matchingPath,
		Domain:              domain,
		RequireTLS:          reqTLS,
		SkipCertValidations: skipValid,
		H2C:                 useH2C,
	}

	//Add Virtual Directory Rule to this Proxy Endpoint
	activatedProxyEndpoint, err := targetProxyEndpoint.AddVirtualDirectoryRule(&newVirtualDirectoryRouter)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Save it to file
	SaveReverseProxyConfig(activatedProxyEndpoint)

	// Update uptime monitor
	UpdateUptimeMonitorTargets()
	utils.SendOK(w)
}

func ReverseProxyDeleteVdir(w http.ResponseWriter, r *http.Request) {
	eptype, err := utils.PostPara(r, "type") //Support root and host
	if err != nil {
		utils.SendErrorResponse(w, "type not defined")
		return
	}

	vdir, err := utils.PostPara(r, "vdir")
	if err != nil {
		utils.SendErrorResponse(w, "vdir matching key not defined")
		return
	}

	var targetEndpoint *dynamicproxy.ProxyEndpoint
	if eptype == "root" {
		targetEndpoint = dynamicProxyRouter.Root
	} else if eptype == "host" {
		//Proxy rule
		matchingPath, err := utils.PostPara(r, "path")
		if err != nil {
			utils.SendErrorResponse(w, "matching path not defined")
			return
		}

		ept, err := dynamicProxyRouter.LoadProxy(matchingPath)
		if err != nil {
			utils.SendErrorResponse(w, "target proxy rule not found")
			return
		}

		targetEndpoint = ept
	} else {
		utils.SendErrorResponse(w, "invalid endpoint type")
		return
	}

	//Delete the Vdir from endpoint
	err = targetEndpoint.RemoveVirtualDirectoryRuleByMatchingPath(vdir)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("Config", "Fail to write vdir rules update to config file", err)
		utils.SendErrorResponse(w, "unable to write changes to file")
		return
	}

	UpdateUptimeMonitorTargets()

	utils.SendOK(w)
}

// Handle update of reverse proxy vdir rules
func ReverseProxyEditVdir(w http.ResponseWriter, r *http.Request) {
	eptype, err := utils.PostPara(r, "type") //Support root and host
	if err != nil {
		utils.SendErrorResponse(w, "type not defined")
		return
	}

	vdir, err := utils.PostPara(r, "vdir")
	if err != nil {
		utils.SendErrorResponse(w, "vdir matching key not defined")
		return
	}

	domain, err := utils.PostPara(r, "domain")
	if err != nil {
		utils.SendErrorResponse(w, "target domain not defined")
		return
	}

	reqTLSForGuard, _ := utils.PostBool(r, "reqTLS")
	if err := validateBackendTarget(strings.TrimSpace(domain), reqTLSForGuard); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Assume false if not given
	reqTLS, _ := utils.PostBool(r, "reqTLS")
	skipValid, _ := utils.PostBool(r, "skipValid")

	var targetEndpoint *dynamicproxy.ProxyEndpoint
	if eptype == "root" {
		targetEndpoint = dynamicProxyRouter.Root

	} else if eptype == "host" {
		//Proxy rule
		matchingPath, err := utils.PostPara(r, "path")
		if err != nil {
			utils.SendErrorResponse(w, "matching path not defined")
			return
		}

		ept, err := dynamicProxyRouter.LoadProxy(matchingPath)
		if err != nil {
			utils.SendErrorResponse(w, "target proxy rule not found")
			return
		}

		targetEndpoint = ept
	} else {
		utils.SendErrorResponse(w, "invalid endpoint type given")
		return
	}

	//Check if the target vdir exists
	if targetEndpoint.GetVirtualDirectoryRuleByMatchingPath(vdir) == nil {
		utils.SendErrorResponse(w, "target virtual directory rule not exists")
		return
	}

	//Overwrite the target endpoint, keeping the enabled state of the old rule
	wasDisabled := targetEndpoint.GetVirtualDirectoryRuleByMatchingPath(vdir).Disabled

	//h2c: a request without the parameter (older scripts) keeps what is stored,
	//except that switching TLS on (tick box or https:// in the target address) drops it,
	//as h2c only exists without TLS
	useH2C, h2cGiven, err := parseVdirH2C(r)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if !h2cGiven {
		useH2C = targetEndpoint.GetVirtualDirectoryRuleByMatchingPath(vdir).H2C && validateVdirH2C(true, reqTLS, domain) == nil
	} else if err := validateVdirH2C(useH2C, reqTLS, domain); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	newVdirRule := dynamicproxy.VirtualDirectoryEndpoint{
		MatchingPath:        vdir,
		Domain:              domain,
		RequireTLS:          reqTLS,
		SkipCertValidations: skipValid,
		Disabled:            wasDisabled,
		H2C:                 useH2C,
	}

	targetEndpoint.RemoveVirtualDirectoryRuleByMatchingPath(vdir)
	activatedProxyEndpoint, err := targetEndpoint.AddVirtualDirectoryRule(&newVdirRule)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Save changes to file
	SaveReverseProxyConfig(activatedProxyEndpoint)

	UpdateUptimeMonitorTargets()

	utils.SendOK(w)
}

// ReverseProxyBulkApplyVdirByForwardAuth bulk-manages a virtual directory across hosts based on
// their Forward Auth state, so the auth callback directory (e.g. Authentik's
// /outpost.goauthentik.io) can be set up or torn down without per-host manual work.
//
//	action=add    -> create the directory on every host that USES Forward Auth
//	action=remove -> remove the directory from every host that does NOT use Forward Auth
//
// Existing directories are only skipped (add) or removed when their target matches the spec
// exactly; a directory at the same path with different settings is reported as a conflict and
// left untouched, so nothing is silently overwritten or deleted.
func ReverseProxyBulkApplyVdirByForwardAuth(w http.ResponseWriter, r *http.Request) {
	action, err := utils.PostPara(r, "action")
	if err != nil || (action != "add" && action != "remove") {
		utils.SendErrorResponse(w, "invalid action, expected 'add' or 'remove'")
		return
	}

	matchingPath, err := utils.PostPara(r, "path")
	if err != nil || strings.TrimSpace(matchingPath) == "" {
		utils.SendErrorResponse(w, "matching path not defined")
		return
	}
	if !strings.HasPrefix(matchingPath, "/") {
		matchingPath = "/" + matchingPath
	}

	domain, err := utils.PostPara(r, "domain")
	if err != nil || strings.TrimSpace(domain) == "" {
		utils.SendErrorResponse(w, "target domain not defined")
		return
	}

	reqTLS, _ := utils.PostBool(r, "reqTLS")
	skipValid, _ := utils.PostBool(r, "skipValid")

	ensurePresent := (action == "add")

	// Collect the target host endpoints first so we don't mutate the map while ranging it.
	// "add" applies to hosts using Forward Auth; "remove" applies to all other hosts.
	targets := []*dynamicproxy.ProxyEndpoint{}
	dynamicProxyRouter.ProxyEndpoints.Range(func(key, value interface{}) bool {
		ep, ok := value.(*dynamicproxy.ProxyEndpoint)
		if !ok {
			return true
		}
		usesForwardAuth := ep.AuthenticationProvider != nil &&
			ep.AuthenticationProvider.AuthMethod == dynamicproxy.AuthMethodForward
		if usesForwardAuth == ensurePresent {
			targets = append(targets, ep)
		}
		return true
	})

	created := []string{}
	removed := []string{}
	skipped := []string{}
	conflicts := []string{}
	failed := []string{}

	for _, ep := range targets {
		existing := ep.GetVirtualDirectoryRuleByMatchingPath(matchingPath)
		switch dynamicproxy.ClassifyBulkVdir(ensurePresent, existing, domain, reqTLS, skipValid) {
		case dynamicproxy.BulkVdirCreate:
			newVdir := dynamicproxy.VirtualDirectoryEndpoint{
				MatchingPath:        matchingPath,
				Domain:              domain,
				RequireTLS:          reqTLS,
				SkipCertValidations: skipValid,
			}
			activatedProxyEndpoint, addErr := ep.AddVirtualDirectoryRule(&newVdir)
			if addErr != nil {
				failed = append(failed, ep.RootOrMatchingDomain)
				continue
			}
			SaveReverseProxyConfig(activatedProxyEndpoint)
			created = append(created, ep.RootOrMatchingDomain)
		case dynamicproxy.BulkVdirRemove:
			// Re-fetch right before deletion: if the vdir was edited concurrently and
			// no longer points at the SSO endpoint, treat it as a conflict instead.
			current := ep.GetVirtualDirectoryRuleByMatchingPath(matchingPath)
			if current == nil || !current.HasSameTarget(domain, reqTLS, skipValid) {
				conflicts = append(conflicts, ep.RootOrMatchingDomain)
				continue
			}
			if removeErr := ep.RemoveVirtualDirectoryRuleByMatchingPath(matchingPath); removeErr != nil {
				failed = append(failed, ep.RootOrMatchingDomain)
				continue
			}
			SaveReverseProxyConfig(ep)
			removed = append(removed, ep.RootOrMatchingDomain)
		case dynamicproxy.BulkVdirSkip:
			skipped = append(skipped, ep.RootOrMatchingDomain)
		case dynamicproxy.BulkVdirConflict:
			conflicts = append(conflicts, ep.RootOrMatchingDomain)
		case dynamicproxy.BulkVdirNoop:
			// Nothing to do on this host
		}
	}

	if len(created) > 0 || len(removed) > 0 {
		UpdateUptimeMonitorTargets()
	}

	js, _ := json.Marshal(map[string]interface{}{
		"action":    action,
		"created":   created,
		"removed":   removed,
		"skipped":   skipped,
		"conflicts": conflicts,
		"failed":    failed,
	})
	utils.SendJSONResponse(w, string(js))
}
