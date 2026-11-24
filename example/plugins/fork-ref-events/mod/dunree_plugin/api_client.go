package dunree_plugin

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/*
	API client helpers (since SDK 1.2.0)

	For the calls a plugin makes to the Dunree plugin API (/plugin/api/...) with
	the API key of its start configuration. They build the address and set the
	"Authorization: Bearer <api_key>" header, so plugin code does not handle the
	key itself:

		resp, err := cfg.DoAPIRequest(http.MethodGet, "/plugin/api/access/list", nil)

	A plugin only gets a key (and these helpers only work) when its manifest has
	PermittedAPIEndpoints, and Dunree only answers the method and path pairs that
	are granted. See docs/plugins/contract.md section 6.
*/

// ErrNoAPIKey is returned by the API helpers when Dunree handed no API key (or no
// port) to this plugin: the manifest has no PermittedAPIEndpoints.
var ErrNoAPIKey = errors.New("dunree_plugin: no API key in the start configuration (the manifest needs permitted_api_endpoints)")

// ErrAPIEndpoint is returned when the endpoint given to an API helper is not a path
// that starts with "/" (an absolute URL is refused, so the key cannot be sent elsewhere).
var ErrAPIEndpoint = errors.New("dunree_plugin: the API endpoint must be a path that starts with \"/\"")

// apiHTTPClient is used by DoAPIRequest. It does not follow redirects, so the key
// is never sent on to another address, and it does not wait forever.
var apiHTTPClient = &http.Client{
	Timeout:       30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// APIURL returns the address of a Dunree plugin API endpoint, for example
// APIURL("/plugin/api/access/list"). The endpoint may carry a query string.
// It returns an empty string, which no HTTP client can send a request to, when
// the endpoint is not a path that starts with one "/" (so "@other.host/x" cannot
// turn the address into one of another host) or when there is no port.
func (c *ConfigureSpec) APIURL(endpoint string) string {
	if c == nil || c.DunreePort <= 0 || !validAPIEndpoint(endpoint) {
		return ""
	}
	return "http://127.0.0.1:" + strconv.Itoa(c.DunreePort) + endpoint
}

// validAPIEndpoint reports whether the endpoint is a path on Dunree: it starts
// with "/" and not with "//"
func validAPIEndpoint(endpoint string) bool {
	return strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "//")
}

// SetAPIAuth sets the "Authorization: Bearer <api_key>" header on a request you
// built yourself. Only use it on requests to Dunree (APIURL): the key is a secret,
// and SetAPIAuth does not look at where the request goes. It does nothing when
// there is no key or no request.
func (c *ConfigureSpec) SetAPIAuth(req *http.Request) {
	if c == nil || c.APIKey == "" || req == nil {
		return
	}
	if req.Header == nil {
		req.Header = http.Header{}
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
}

// NewAPIRequest builds a request to a Dunree plugin API endpoint with the
// Authorization header set. Send it with your own http.Client, or use DoAPIRequest.
// Set a Content-Type yourself when you send a body.
func (c *ConfigureSpec) NewAPIRequest(method string, endpoint string, body io.Reader) (*http.Request, error) {
	if c == nil || c.APIKey == "" || c.DunreePort <= 0 {
		return nil, ErrNoAPIKey
	}
	if !validAPIEndpoint(endpoint) {
		return nil, ErrAPIEndpoint
	}
	req, err := http.NewRequest(method, c.APIURL(endpoint), body)
	if err != nil {
		return nil, err
	}
	c.SetAPIAuth(req)
	return req, nil
}

// DoAPIRequest builds the request as NewAPIRequest does and sends it. The caller
// closes the body of the response. Redirects are not followed and the call gives
// up after 30 seconds. A status other than 200 is not an error here: check
// resp.StatusCode (Dunree answers 401 for a key it does not know and for an
// endpoint that is not granted).
func (c *ConfigureSpec) DoAPIRequest(method string, endpoint string, body io.Reader) (*http.Response, error) {
	req, err := c.NewAPIRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}
	return apiHTTPClient.Do(req)
}
