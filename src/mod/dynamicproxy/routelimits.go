package dynamicproxy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
)

/*
	Per route request limits (dual proxy plan, Phase 2 slice C).

	MaxRequestBodyBytes, RequestTimeout and UpstreamDialTimeout of a ProxyEndpoint. A rule that sets none of them
	(every old config) takes the first return of applyRouteLimits: the request is passed on untouched.
*/

// maxRouteTimeoutSeconds caps RequestTimeout / UpstreamDialTimeout (one day, a larger value is a typo)
const maxRouteTimeoutSeconds = 24 * 3600

// ValidateRouteLimits checks the limit fields of an endpoint before it is saved
func ValidateRouteLimits(ep *ProxyEndpoint) error {
	if ep.MaxRequestBodyBytes < 0 {
		return errors.New("the maximum request body size cannot be negative")
	}
	if ep.RequestTimeout < 0 || ep.RequestTimeout > maxRouteTimeoutSeconds {
		return errors.New("the request timeout must be between 0 (off) and 86400 seconds")
	}
	if ep.UpstreamDialTimeout < 0 || ep.UpstreamDialTimeout > maxRouteTimeoutSeconds {
		return errors.New("the upstream connect timeout must be between 0 (default) and 86400 seconds")
	}
	return nil
}

// applyRouteLimits enforces the endpoint's limits on r. It returns the request to continue with, a cancel function
// the caller must defer, and false when the request was already answered (413).
func applyRouteLimits(w http.ResponseWriter, r *http.Request, ep *ProxyEndpoint) (*http.Request, context.CancelFunc, bool) {
	noop := func() {}
	if ep == nil || (ep.MaxRequestBodyBytes <= 0 && ep.RequestTimeout <= 0 && ep.UpstreamDialTimeout <= 0) {
		return r, noop, true
	}
	if max := ep.MaxRequestBodyBytes; max > 0 {
		if r.ContentLength > max {
			w.Header().Set("Connection", "close")
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return r, noop, false
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
	}
	ctx := r.Context()
	cancel := noop
	if ep.UpstreamDialTimeout > 0 {
		ctx = dpcore.WithDialTimeout(ctx, time.Duration(ep.UpstreamDialTimeout)*time.Second)
	}
	//Genuine WebSocket upgrades (routed to the WebSocket handler) and CONNECT tunnels live far longer than a request by design.
	//Any other Upgrade header is an ordinary request as far as the timeout is concerned.
	if ep.RequestTimeout > 0 && !isWebSocketRequest(r) && !strings.EqualFold(r.Method, http.MethodConnect) {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(ep.RequestTimeout)*time.Second)
	}
	if ctx != r.Context() {
		r = r.WithContext(ctx)
	}
	return r, cancel, true
}

// routeLimitStatus maps an upstream error to the status a route limit calls for:
// 413 when the request body outgrew MaxRequestBodyBytes, 504 when RequestTimeout ran out.
func routeLimitStatus(err error, r *http.Request, ep *ProxyEndpoint) (int, bool) {
	if err == nil || ep == nil {
		return 0, false
	}
	//Headers (and part of the body) are already with the client: a limit hit while copying the body cannot
	//be answered with a second status line. The caller aborts or leaves the connection as it is.
	if errors.Is(err, dpcore.ErrResponseAborted) {
		return 0, false
	}
	var tooBig *http.MaxBytesError
	if ep.MaxRequestBodyBytes > 0 && errors.As(err, &tooBig) {
		return http.StatusRequestEntityTooLarge, true
	}
	if ep.RequestTimeout > 0 && errors.Is(r.Context().Err(), context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, true
	}
	return 0, false
}
