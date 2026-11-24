//go:build unix

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/textproto"
	"strings"
)

/*
	Verdict rules

	A copy of the rules Dunree applies to the answer of a filter call
	(src/mod/plugins/hooks_validate.go, sanitizeVerdict). The kit does not import
	Dunree, so the two could drift apart; testdata/verdicts.json is a list of
	verdicts with the expected outcome that is checked against this copy
	(TestVerdictFixtures) and against Dunree itself
	(TestConformanceKitVerdictRulesMatchDunree in src/mod/plugins).
*/

const (
	maxDenyBodyBytes    = 64 * 1024
	maxVerdictBytes     = 256 * 1024
	maxHeaderOps        = 32
	maxHeaderValueBytes = 8 * 1024
	maxPathBytes        = 4 * 1024
	maxQueryBytes       = 8 * 1024
	maxDenyHeaders      = 16
)

type headerOps struct {
	Add    map[string]string `json:"add,omitempty"`
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

type filterVerdict struct {
	Version int    `json:"version"`
	Action  string `json:"action"`
	Reason  string `json:"reason,omitempty"`
	Deny    *struct {
		Status  int               `json:"status,omitempty"`
		Body    string            `json:"body,omitempty"`
		Headers map[string]string `json:"headers,omitempty"`
	} `json:"deny,omitempty"`
	Modify *struct {
		RequestHeaders  *headerOps `json:"request_headers,omitempty"`
		Path            *string    `json:"path,omitempty"`
		Query           *string    `json:"query,omitempty"`
		ResponseHeaders *headerOps `json:"response_headers,omitempty"`
	} `json:"modify,omitempty"`
}

var framingHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Proxy-Connection": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
	"Content-Length": true, "Content-Encoding": true, "Expect": true,
}

var identityRequestHeaders = map[string]bool{
	"Host": true, "X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true,
	"X-Forwarded-Port": true, "X-Real-Ip": true, "Forwarded": true, "Origin-Host": true,
}

var protectedResponseHeaders = map[string]bool{"Content-Range": true, "Accept-Ranges": true, "Content-Length": true}

var denyHeaderAllowList = map[string]bool{
	"Content-Type": true, "Cache-Control": true, "Retry-After": true, "Content-Language": true,
	"Www-Authenticate": true, "Content-Security-Policy": true, "Referrer-Policy": true,
	"Expires": true, "Pragma": true,
}

func validHeaderName(name string) error {
	if name == "" || len(name) > 128 {
		return errors.New("invalid header name length")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return fmt.Errorf("invalid character in header name %q", name)
		}
	}
	return nil
}

func validHeaderValue(v string) error {
	if len(v) > maxHeaderValueBytes {
		return errors.New("header value too large")
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return errors.New("control character in header value")
		}
	}
	return nil
}

func checkHeaderOp(response bool, op, rawName string) error {
	if err := validHeaderName(rawName); err != nil {
		return err
	}
	name := textproto.CanonicalMIMEHeaderKey(rawName)
	if framingHeaders[name] {
		return fmt.Errorf("header %s cannot be modified by plugins", name)
	}
	if !response {
		if identityRequestHeaders[name] {
			return fmt.Errorf("request header %s cannot be modified by plugins", name)
		}
		if strings.HasPrefix(name, "X-Dunree-") || strings.HasPrefix(name, "X-Zoraxy-") { // legacy-compat: both prefixes stay reserved
			return fmt.Errorf("request header %s is reserved", name)
		}
		return nil
	}
	if protectedResponseHeaders[name] {
		return fmt.Errorf("response header %s cannot be modified by plugins", name)
	}
	if name == "Set-Cookie" && op != "add" {
		return errors.New("Set-Cookie can only be added, not set or removed")
	}
	return nil
}

func checkHeaderOps(response bool, ops *headerOps) error {
	if ops == nil {
		return nil
	}
	if len(ops.Add)+len(ops.Set)+len(ops.Remove) > maxHeaderOps {
		return errors.New("too many header operations")
	}
	total := 0
	for op, set := range map[string]map[string]string{"add": ops.Add, "set": ops.Set} {
		for k, v := range set {
			if err := checkHeaderOp(response, op, k); err != nil {
				return err
			}
			if err := validHeaderValue(v); err != nil {
				return err
			}
			total += len(v)
		}
	}
	for _, k := range ops.Remove {
		if err := checkHeaderOp(response, "remove", k); err != nil {
			return err
		}
	}
	if total > 4*maxHeaderValueBytes {
		return errors.New("header operations too large")
	}
	return nil
}

func validateRewritePath(p string) error {
	if p == "" || len(p) > maxPathBytes {
		return errors.New("invalid path length")
	}
	if p[0] != '/' || strings.HasPrefix(p, "//") {
		return errors.New("path must be absolute and must not start with //")
	}
	if strings.ContainsAny(p, "?#\\") {
		return errors.New("path must not contain ?, # or backslash")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return errors.New("control character in path")
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return errors.New("path must not contain .. segments")
		}
	}
	return nil
}

func validateRewriteQuery(q string) error {
	if len(q) > maxQueryBytes {
		return errors.New("query too large")
	}
	if strings.HasPrefix(q, "?") || strings.Contains(q, "#") {
		return errors.New("query must be the raw query without ? or #")
	}
	for i := 0; i < len(q); i++ {
		if q[i] < 0x20 || q[i] == 0x7f || q[i] == ' ' {
			return errors.New("control character or space in query")
		}
	}
	return nil
}

// validateVerdictBody checks the body of a filter answer for a stage the way Dunree
// does: size, JSON, then the verdict rules. It returns the action on success.
func validateVerdictBody(stage string, body []byte) (string, error) {
	if len(body) > maxVerdictBytes {
		return "", fmt.Errorf("the answer is larger than %d bytes", maxVerdictBytes)
	}
	var v filterVerdict
	if err := json.Unmarshal(body, &v); err != nil {
		return "", fmt.Errorf("the answer is not a verdict in JSON: %v", err)
	}
	return v.Action, validateVerdict(stage, &v)
}

func validateVerdict(stage string, v *filterVerdict) error {
	if v.Version > hookAPIVersion {
		return fmt.Errorf("unsupported verdict version %d", v.Version)
	}
	isResponse := stage == "response"
	switch v.Action {
	case "allow":
		return nil
	case "capture":
		if isResponse {
			return errors.New("capture is not valid at the response stage")
		}
		return nil
	case "deny":
		if isResponse {
			return errors.New("deny is not valid at the response stage")
		}
		if v.Deny == nil {
			return nil
		}
		status := v.Deny.Status
		if status == 0 {
			status = 403
		}
		if status < 400 || status > 599 {
			return fmt.Errorf("deny status %d out of range 400-599", v.Deny.Status)
		}
		if len(v.Deny.Body) > maxDenyBodyBytes {
			return errors.New("deny body too large")
		}
		if len(v.Deny.Headers) > maxDenyHeaders {
			return errors.New("too many deny headers")
		}
		for k, val := range v.Deny.Headers {
			if err := validHeaderName(k); err != nil {
				return err
			}
			name := textproto.CanonicalMIMEHeaderKey(k)
			if !denyHeaderAllowList[name] && !strings.HasPrefix(name, "X-") {
				return fmt.Errorf("deny header %s is not allowed", name)
			}
			if strings.HasPrefix(name, "X-Dunree-") || strings.HasPrefix(name, "X-Zoraxy-") { // legacy-compat: both prefixes stay reserved
				return fmt.Errorf("deny header %s is reserved", name)
			}
			if err := validHeaderValue(val); err != nil {
				return err
			}
		}
		return nil
	case "modify":
		m := v.Modify
		if m == nil {
			return errors.New("modify verdict without modify object")
		}
		if isResponse {
			if m.RequestHeaders != nil || m.Path != nil || m.Query != nil {
				return errors.New("only response_headers can be modified at the response stage")
			}
			return checkHeaderOps(true, m.ResponseHeaders)
		}
		if m.ResponseHeaders != nil {
			return errors.New("response_headers can only be modified at the response stage")
		}
		if err := checkHeaderOps(false, m.RequestHeaders); err != nil {
			return err
		}
		if m.Path != nil {
			if err := validateRewritePath(*m.Path); err != nil {
				return err
			}
		}
		if m.Query != nil {
			if err := validateRewriteQuery(*m.Query); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unknown action %q", v.Action)
}
