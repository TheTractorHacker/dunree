package logger

/*
	Traffic Log

	This script log the traffic of HTTP requests

*/
import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Log HTTP request. Note that this must run in go routine to prevent any blocking
// in reverse proxy router.
//
// clientIP must be resolved by the caller (e.g. via the access rule / trusted proxy
// aware resolver) instead of being derived here, so that untrusted proxy headers
// (X-Forwarded-For, X-Real-IP, etc.) cannot be used to spoof the logged source IP.
//
// Line format: [time] [router:class] [origin:host] [client: ip] [useragent: ua] METHOD URI STATUS
// With the opt-in ECH field (Logger.ECHField returns a value, HTTPS requests only) one more bracket follows the
// user agent: ... [useragent: ua] [ech: accepted outer=public.example.com] METHOD URI STATUS
func (l *Logger) LogHTTPRequest(r *http.Request, reqclass string, statusCode int, downstreamHostname string, upstreamHostname string, clientIP string) {
	echField := l.echField(r)
	//Read the request here, not in the goroutine: the proxy goes on rewriting r.Header while the line is written
	//(a concurrent map read and write is a fatal error, not a panic that could be recovered)
	userAgent, method, requestURI := r.UserAgent(), r.Method, r.RequestURI
	go func() {
		l.ValidateAndUpdateLogFilepath()
		if l.logger == nil || l.file == nil {
			//logger is not initiated. Do not log http request
			return
		}
		statusCodeString := strconv.Itoa(statusCode)

		//Pretty print for debugging
		//fmt.Printf("------------\nRequest URL: %s (class: %s) \nUpstream Hostname: %s\nDownstream Hostname: %s\nStatus Code: %s\n", r.URL, reqclass, upstreamHostname, downstreamHostname, statusCodeString)
		l.logger.Println("[" + time.Now().Format("2006-01-02 15:04:05.000000") + "] [router:" + reqclass + "] [origin:" + downstreamHostname + "] [client: " + clientIP + "] [useragent: " + userAgent + "] " + echField + method + " " + requestURI + " " + statusCodeString)
	}()
}

// echField returns the optional "[ech: ...] " part of a request log line (with its trailing space), or ""
func (l *Logger) echField(r *http.Request) string {
	if v := l.echValue(r); v != "" {
		return "[ech: " + v + "] "
	}
	return ""
}

// echValue asks the optional hook and keeps its answer from breaking the line format
func (l *Logger) echValue(r *http.Request) string {
	if l.ECHField == nil || r == nil {
		return ""
	}
	return strings.Map(func(c rune) rune {
		if c == ']' || c == '[' || c < 0x20 || c == 0x7f {
			return '?'
		}
		return c
	}, l.ECHField(r))
}
