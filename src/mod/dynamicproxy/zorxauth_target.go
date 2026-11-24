package dynamicproxy

// ZorxAuthSessionTarget tells the ZorxAuth portal whether it may send a one-time
// session code to host (zorxauth.AuthRouter.SessionTargetPolicy).
//
// protected: an enabled proxy rule (matching domain, wildcard or alias) serves
// the host and authenticates with ZorxAuth. The default site never runs an
// authentication provider, so a host no rule matches is not protected.
//
// httpsOnly: the rule is not reachable over plain http, so the code must not be
// sent to an http:// URL. Plain http reaches a rule when the proxy runs without
// TLS, when the rule bypasses global TLS, or through its own listening ports.
func (router *Router) ZorxAuthSessionTarget(host string) (protected bool, httpsOnly bool) {
	if router == nil || router.ProxyEndpoints == nil || router.Option == nil {
		return false, false
	}
	sep := router.GetProxyEndpointFromHostname(host)
	if sep == nil || sep.Disabled || sep.AuthenticationProvider == nil ||
		sep.AuthenticationProvider.AuthMethod != AuthMethodZorxAuth {
		return false, false
	}
	return true, router.Option.UseTls && !sep.BypassGlobalTLS && len(sep.ListeningPorts) == 0
}
