package notify

// EventAuthDrift is raised by the authentication audit (issue #216) when a proxy rule carries an auth:* tag
// that does not name the login the rule enforces, for example a rule tagged auth:oauth2 whose authentication
// is "none". Opt-in: only a destination that lists the event receives it.
//
//	auth.drift  warning  security  proxy rule  tagged, method, wanted
const EventAuthDrift = "auth.drift"

func init() {
	Catalog = append(Catalog, EventInfo{Name: EventAuthDrift, Severity: SevWarning, Title: "Login tag does not match the login", OptIn: true})
}
