// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package wirecompat

/*
	Values, as opposed to names (plan rows 13, 28, 12 of docs/rebrand/plan.md).

	A header can be sent twice under two names. A value cannot: a User-Agent or an
	environment of a hook command has one value per name. So:

	  - User-Agent: the Dunree token, and while EmitLegacy is on the inherited token
	    appended in parentheses. An allow-list at an upstream that matches the old
	    token as a substring keeps matching. // legacy-compat
	  - environment of hook commands: DUNREE_<NAME>, and while EmitLegacy is on the
	    same value again as ZORAXY_<NAME>. // legacy-compat
*/

const (
	EnvPrefix       = "DUNREE_"
	LegacyEnvPrefix = "ZORAXY_" // legacy-compat
)

// UserAgent returns the User-Agent for an outbound request:
// UserAgent("Dunree-HealthCheck", "Zoraxy-HealthCheck") = "Dunree-HealthCheck (Zoraxy-HealthCheck)" while
// EmitLegacy is on, "Dunree-HealthCheck" when it is off.
func UserAgent(token, legacyToken string) string {
	if legacyToken == "" || !EmitLegacy() {
		return token
	}
	return token + " (" + legacyToken + ")"
}

// Env renders NAME=value pairs as DUNREE_NAME=value and, while EmitLegacy is on, also as
// ZORAXY_NAME=value (in that order: the Dunree names first, then the inherited ones).
func Env(pairs [][2]string) []string {
	out := make([]string, 0, 2*len(pairs))
	for _, p := range pairs {
		out = append(out, EnvPrefix+p[0]+"="+p[1])
	}
	if EmitLegacy() {
		for _, p := range pairs {
			out = append(out, LegacyEnvPrefix+p[0]+"="+p[1])
		}
	}
	return out
}
