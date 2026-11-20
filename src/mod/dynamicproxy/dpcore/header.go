package dpcore

import (
	"net"
	"net/http"
	"strings"
)

/*
	Header.go

	This script handles headers rewrite and remove
	in dpcore.

	Added in Zoraxy v3.0.6 by tobychui
*/

// removeHeaders Remove hop-by-hop headers listed in the "Connection" header, Remove hop-by-hop headers.
func removeHeaders(header http.Header) {
	// Remove hop-by-hop headers listed in the "Connection" header.
	if c := header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				header.Del(f)
			}
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopHeaders {
		if header.Get(h) != "" {
			header.Del(h)
		}
	}

	//Restore the Upgrade header if any
	if header.Get("Zr-Origin-Upgrade") != "" {
		header.Set("Upgrade", header.Get("Zr-Origin-Upgrade"))
		header.Del("Zr-Origin-Upgrade")
	}
}

// setNoCacheHeader force set Cache-Control to no-store, independent of hop-by-hop removal
func setNoCacheHeader(header http.Header) {
	header.Del("Cache-Control")
	header.Set("Cache-Control", "no-store")
}

// rewriteUserAgent rewrite the user agent based on incoming request
func rewriteUserAgent(header http.Header, UA string) {
	//Hide Go-HTTP-Client UA if the client didnt sent us one
	if header.Get("User-Agent") == "" {
		// If the outbound request doesn't have a User-Agent header set,
		// don't send the default Go HTTP client User-Agent
		header.Del("User-Agent")
		header.Set("User-Agent", UA)
	}
}

// Add X-Forwarded-For Header and rewrite X-Real-Ip according to sniffing logics
func addXForwardedForHeader(req *http.Request) {
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}

		if req.Header.Get("X-Real-Ip") == "" {
			//Check if CF-Connecting-IP header exists
			CF_Connecting_IP := req.Header.Get("CF-Connecting-IP")
			Fastly_Client_IP := req.Header.Get("Fastly-Client-IP")
			if CF_Connecting_IP != "" {
				//Use CF Connecting IP
				req.Header.Set("X-Real-Ip", CF_Connecting_IP)
			} else if Fastly_Client_IP != "" {
				//Use Fastly Client IP
				req.Header.Set("X-Real-Ip", Fastly_Client_IP)
			} else {
				// Not exists. Fill it in with first entry in X-Forwarded-For
				ips := strings.Split(clientIP, ",")
				if len(ips) > 0 {
					req.Header.Set("X-Real-Ip", strings.TrimSpace(ips[0]))
				}
			}
		}

	}
}

// injectUserDefinedHeaders inject the user headers from slice
// if a value is empty string, the key will be removed from header.
// if a key is empty string, the function will return immediately
func injectUserDefinedHeaders(header http.Header, userHeaders [][]string) {
	for _, userHeader := range userHeaders {
		if len(userHeader) == 0 {
			//End of header slice
			return
		}
		headerKey := userHeader[0]
		headerValue := userHeader[1]
		if headerValue == "" {
			//Remove header from head
			header.Del(headerKey)
			continue
		}

		//Default: Set header value
		header.Del(headerKey) //Remove header if it already exists
		header.Set(headerKey, headerValue)
	}
}

// injectHardenedHeaders applies the hardened security header preset to an upstream response. A header the
// upstream already sent is left alone unless override is set. Content-Security-Policy is never replaced: the preset
// only carries a frame-ancestors directive, which is added as a further policy header (override only) when the
// existing policy has none, and an existing frame-ancestors is always kept.
func injectHardenedHeaders(header http.Header, list [][]string, override bool) {
	for _, kv := range list {
		if len(kv) < 2 || kv[0] == "" || kv[1] == "" {
			continue
		}
		existing := header.Values(kv[0])
		if len(existing) == 0 {
			header.Set(kv[0], kv[1])
			continue
		}
		if !override {
			continue
		}
		if strings.EqualFold(kv[0], "Content-Security-Policy") {
			joined := strings.Join(existing, ", ")
			if !strings.Contains(strings.ToLower(joined), "frame-ancestors") {
				header.Add(kv[0], kv[1]) //a second policy header only ever adds restrictions
			}
			continue
		}
		header.Set(kv[0], kv[1])
	}
}
