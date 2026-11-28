package vip

import "regexp"

// fieldLabels maps every field a validator can name to an i18n key, so no raw
// path such as members[1].priority reaches the page.
var fieldLabels = map[string]string{
	"transport":               "vip.field.transport",
	"auth":                    "vip.field.auth",
	"vrid":                    "vip.field.vrid",
	"advertInt":               "vip.field.advertInt",
	"preemptDelay":            "vip.field.preemptDelay",
	"garpRefresh":             "vip.field.garpRefresh",
	"health.interval":         "vip.field.health.interval",
	"health.timeout":          "vip.field.health.timeout",
	"health.fall":             "vip.field.health.fall",
	"health.rise":             "vip.field.health.rise",
	"password":                "vip.field.password",
	"clusterPass":             "vip.field.clusterPass",
	"members":                 "vip.field.members",
	"vip":                     "vip.field.vip",
	"prefix":                  "vip.field.prefix",
	"main":                    "vip.field.main",
	"members[].label":         "vip.field.member.label",
	"members[].address":       "vip.field.member.address",
	"members[].priority":      "vip.field.member.priority",
	"members[].interfaceHint": "vip.field.member.interfaceHint",
	"interface":               "vip.field.local.interface",
	"priorityOverride":        "vip.field.local.priorityOverride",
	"sourceAddress":           "vip.field.local.sourceAddress",
	"healthTarget":            "vip.field.local.healthTarget",
}

var reMemberIndex = regexp.MustCompile(`^members\[[0-9]+\]`)

// FieldLabelKey returns the i18n key for a FieldError.Field and, for member
// fields, the member index (-1 for none). ok is false for an unknown field.
func FieldLabelKey(field string) (key string, member int, ok bool) {
	member = -1
	if loc := reMemberIndex.FindString(field); loc != "" {
		n := 0
		for _, c := range loc[len("members["):] {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		member = n
		field = "members[]" + field[len(loc):]
	}
	key, ok = fieldLabels[field]
	return
}
