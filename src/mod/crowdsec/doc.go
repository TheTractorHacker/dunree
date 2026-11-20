// Package crowdsec is a CrowdSec "remediation component" (bouncer) for Zoraxy. It talks to a CrowdSec Local API
// (LAPI) that the administrator runs, keeps the ban decisions in a bounded in-memory cache (stream mode) and tells
// the request path whether a client address is currently decided against.
//
// Only documented LAPI interfaces are used:
//
//   - Bouncer authentication: the API key travels in the X-Api-Key header; a missing or wrong key is answered with
//     HTTP 403.  https://docs.crowdsec.net/docs/local_api/bouncers
//   - Stream mode: GET /v1/decisions/stream?startup=true returns the full state once, afterwards
//     GET /v1/decisions/stream (startup=false) returns only the changes since the last pull. The answer is a JSON
//     object with two arrays "new" and "deleted" (each null when empty). The initial answer may contain past deleted
//     decisions. A decision has the fields id, origin, type, scope, value, duration and scenario; duration is a Go
//     style string such as "3h59m57.641708614s". The recommended pull period is 10 seconds.
//     https://docs.crowdsec.net/docs/local_api/bouncers and https://docs.crowdsec.net/docs/contributing/specs/bouncer_appsec_specs
//   - Single lookup: GET /v1/decisions?ip=<address> returns the decisions that apply to the address (a range
//     decision that contains it included) and the JSON value null when there is none. Used for the connection test.
//
// Not implemented (documented as known limits): TLS client certificate authentication to the LAPI
// (https://docs.crowdsec.net/docs/local_api/tls_auth), the optional scopes/origins/types filters of the stream, reporting
// alerts back to CrowdSec, and any replication between two Zoraxy instances (each one queries the same LAPI).
//
// Everything is opt-in: with Settings.Enabled false nothing here runs and no request is touched. The first time it
// is enabled the mode is "log only": decisions are matched and counted but never enforced.
package crowdsec
