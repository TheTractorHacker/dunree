package zorxauth

import (
	"bytes"
	"encoding/json"
)

/*
	Helpers for the cluster settings sync (primary to followers, fork issue #81).
	The sync itself lives in mod/cluster and src/cluster_settings.go; this file
	only knows which parts of a ZorxAuth record belong to one node.
*/

// SharedSessionKey, when set before NewAuthRouter, switches sessions to signed
// tokens (see shared_session.go). The main program sets it from the cluster
// secret when shared SSO portal sessions are switched on; empty keeps the default.
var SharedSessionKey []byte

// OptionsKey is the key of the options record in the DB_NAME table.
const OptionsKey = "options"

// SyncedSettingKeys lists the keys of the DB_NAME table a cluster primary
// offers to its followers.
func SyncedSettingKeys() []string { return []string{OptionsKey, sessionsNotBeforeKey} }

// ExportUserForSync returns a user record without the passkey counters, which
// change on every passkey login and belong to the node that saw the login.
func ExportUserForSync(raw []byte) []byte {
	var u User
	if json.Unmarshal(raw, &u) != nil {
		return raw
	}
	for i := range u.PasskeyCredentials {
		u.PasskeyCredentials[i].SignCount = 0
		u.PasskeyCredentials[i].CloneWarning = false
		u.PasskeyCredentials[i].LastUsedAt = 0
	}
	out, err := json.Marshal(u)
	if err != nil {
		return raw
	}
	return out
}

// MergeSyncedUser returns the record a follower stores for a synced user: the
// primary's record with this node's own passkey counters kept.
func MergeSyncedUser(incoming, local []byte) []byte {
	var in, loc User
	if json.Unmarshal(incoming, &in) != nil || len(local) == 0 || json.Unmarshal(local, &loc) != nil {
		return incoming
	}
	for i := range in.PasskeyCredentials {
		for _, lc := range loc.PasskeyCredentials {
			if bytes.Equal(lc.ID, in.PasskeyCredentials[i].ID) {
				in.PasskeyCredentials[i].SignCount = lc.SignCount
				in.PasskeyCredentials[i].CloneWarning = lc.CloneWarning
				in.PasskeyCredentials[i].LastUsedAt = lc.LastUsedAt
			}
		}
	}
	out, err := json.Marshal(in)
	if err != nil {
		return incoming
	}
	return out
}

// ExportOptionsForSync returns the options without the config folder, which is
// a path on the exporting node.
func ExportOptionsForSync(raw []byte) []byte {
	var o AuthRouterOptions
	if json.Unmarshal(raw, &o) != nil {
		return raw
	}
	o.ConfigFolderPath = ""
	out, err := json.Marshal(o)
	if err != nil {
		return raw
	}
	return out
}

// MergeSyncedOptions returns the options a follower stores: the primary's with
// this node's config folder and, if keepGatewayPort, its own gateway port.
func MergeSyncedOptions(incoming, local []byte, keepGatewayPort bool) []byte {
	var in, loc AuthRouterOptions
	if json.Unmarshal(incoming, &in) != nil {
		return incoming
	}
	if len(local) > 0 && json.Unmarshal(local, &loc) == nil {
		in.ConfigFolderPath = loc.ConfigFolderPath
		if keepGatewayPort && loc.GatewayPort > 0 {
			in.GatewayPort = loc.GatewayPort
		}
	}
	out, err := json.Marshal(in)
	if err != nil {
		return incoming
	}
	return out
}

// RestoreGatewayPort returns the current options with the gateway port this
// node had on its own: the one in saved, or the built-in default when the node
// had no options record (saved empty) back then.
func RestoreGatewayPort(current, saved []byte) []byte {
	var cur, old AuthRouterOptions
	if json.Unmarshal(current, &cur) != nil {
		return current
	}
	port := getDefaultOptions().GatewayPort
	if len(saved) > 0 && json.Unmarshal(saved, &old) == nil && old.GatewayPort > 0 {
		port = old.GatewayPort
	}
	cur.GatewayPort = port
	out, err := json.Marshal(cur)
	if err != nil {
		return current
	}
	return out
}

// userWriteRefused answers a self-service change (password, 2FA, passkeys) on
// a node whose user list is a copy of another node's: the change would be
// overwritten by the next sync, so it is refused with a reason instead.
func (ar *AuthRouter) userWriteRefused() bool {
	return ar.UsersManagedElsewhere != nil && ar.UsersManagedElsewhere()
}
