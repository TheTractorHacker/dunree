package dynamicproxy

import (
	"context"
	"net/http"
	"net/textproto"

	"github.com/TheTractorHacker/dunree/mod/statistic"
)

/*
	Statistics source headers

	The statistics are written when a request is finished, from the same
	*http.Request the rules engine and the request scripts are allowed to
	change (set / remove request header). A rule such as "remove Referer
	before the upstream sees it" would therefore also blank the referring
	site in the statistics. keepStatSource takes a copy of what the client
	sent the first time one of those headers is about to change, and
	statSourceOf hands that copy to the statistics.
*/

type statSourceKey struct{}

// Headers the statistics read (statistic.RefererSourceFromRequest)
var statSourceHeaders = map[string]bool{
	"Referer": true, "Origin": true, "User-Agent": true,
	"Sec-Fetch-Site": true, "Sec-Fetch-Mode": true, "Sec-Fetch-Dest": true, "Sec-Fetch-User": true,
}

// keepStatSource must be called before a request header is set or removed by configuration
func keepStatSource(r *http.Request, header string) {
	if r == nil || !statSourceHeaders[textproto.CanonicalMIMEHeaderKey(header)] {
		return
	}
	if _, kept := r.Context().Value(statSourceKey{}).(*statistic.RefererSource); kept {
		return
	}
	src := statistic.RefererSourceFromRequest(r)
	*r = *r.WithContext(context.WithValue(r.Context(), statSourceKey{}, &src))
}

// statSourceOf returns the statistics headers of a request as the client sent them
func statSourceOf(r *http.Request) statistic.RefererSource {
	if src, kept := r.Context().Value(statSourceKey{}).(*statistic.RefererSource); kept {
		return *src
	}
	return statistic.RefererSourceFromRequest(r)
}
