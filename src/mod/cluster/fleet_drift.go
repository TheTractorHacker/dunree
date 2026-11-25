package cluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/TheTractorHacker/dunree/mod/confpack"
)

/*
	Fleet drift detection (non secret material only)

	Each node reports one hash per managed scope in its heartbeat; the hub computes the same hashes from
	the bundle it would send to that node and compares them. A scope whose hashes differ is "drifted".

	What goes into a hash: the path of every managed file and, for JSON files, the document with every
	credential field redacted (confpack.CanonicalNonSecret; keys sorted, so formatting does not matter).
	Private keys (*.key, anything holding a PRIVATE KEY block) contribute only their path. A file that is
	missing on the node contributes a "missing" marker. Credential fields are redacted by name (see
	confpack.SensitiveKey), so a change that only touches one is not seen here (the node's older "managed
	files were edited" flag, which hashes the raw files, still covers it).

	Limits, stated plainly: a file that is not JSON (a script, a raw text file) is hashed whole, and a credential
	stored under a field name the redactor does not recognise stays in the JSON. The hash is an unsalted SHA-256, so
	whoever sees a heartbeat (the hub operator) can test guesses against a LOW ENTROPY value in such a file. Keep
	secrets out of managed files; per cluster keyed hashing is a known follow-up.
*/

const maxScopeHashes = 24

type driftItem struct {
	path    string
	data    []byte
	missing bool
}

func driftMaterial(it driftItem) []byte {
	if it.missing {
		return []byte("missing")
	}
	low := strings.ToLower(it.path)
	if strings.HasSuffix(low, ".key") || bytes.Contains(it.data, []byte("PRIVATE KEY-----")) {
		return []byte("private-key-omitted")
	}
	if strings.HasSuffix(low, ".json") || strings.HasSuffix(low, ".config") {
		return confpack.CanonicalNonSecret(it.data)
	}
	return it.data
}

func hashDriftItems(items []driftItem) string {
	sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
	h := sha256.New()
	for _, it := range items {
		m := driftMaterial(it)
		h.Write([]byte(it.path))
		h.Write([]byte{0})
		h.Write([]byte(strconv.Itoa(len(m))))
		h.Write([]byte{0})
		h.Write(m)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// scopeHashesFromFiles groups already resolved bundle files by scope (the hub side).
func scopeHashesFromFiles(files []FileEntry) map[string]string {
	by := map[string][]driftItem{}
	for _, f := range files {
		if !validEntryPath(f.Path, ManagedRoots(true)) {
			continue
		}
		if s, ok := scopeForPath(f.Path); ok {
			by[s.Name()] = append(by[s.Name()], driftItem{path: f.Path, data: f.Data})
		}
	}
	out := map[string]string{}
	for sc, items := range by {
		out[sc] = hashDriftItems(items)
	}
	return out
}

// localScopeHashes hashes the files a node manages as they are on disk now (the node side).
func localScopeHashes(confDir string, managed map[string][]string) map[string]string {
	out := map[string]string{}
	for sc, keys := range managed {
		var items []driftItem
		for _, k := range keys {
			if !validEntryPath(k, ManagedRoots(true)) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(confDir, filepath.FromSlash(k)))
			items = append(items, driftItem{path: k, data: b, missing: err != nil})
		}
		if len(items) > 0 {
			out[sc] = hashDriftItems(items)
		}
	}
	return out
}

func sanitizeScopeHashes(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		if len(out) >= maxScopeHashes {
			break
		}
		out[trimTo(k, 24)] = trimTo(v, 64)
	}
	return out
}

// DriftedScopes lists the scopes whose non secret content differs between what the node reports and
// what the hub would send it. A scope the node reports but the hub no longer ships counts as drifted; a scope
// the hub ships but the node did not report is "unchecked" (an older node, or one that has not applied it yet),
// not drifted: that avoids a false alarm right after an upgrade.
func DriftedScopes(node, desired map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for sc, hv := range desired {
		seen[sc] = true
		if nv, ok := node[sc]; ok && nv != hv {
			out = append(out, sc)
		}
	}
	for sc := range node {
		if !seen[sc] {
			out = append(out, sc)
		}
	}
	sort.Strings(out)
	return out
}

// DesiredScopeHashes returns the per scope hashes of the bundle the node should be running (nil when
// nothing is published or the bundle cannot be built). Memoised like DesiredHash.
func (h *Hub) DesiredScopeHashes(id string) map[string]string {
	h.mu.Lock()
	n := h.st.Nodes[id]
	if n == nil {
		h.mu.Unlock()
		return nil
	}
	cp := *n
	sel, vars := h.effectiveLocked(n)
	ver := h.desiredVersionLocked(n)
	h.mu.Unlock()
	if ver == 0 || len(sel.Scopes) == 0 {
		return nil
	}
	memo := hashStrings(strconv.FormatInt(ver, 10), strings.Join(sel.Scopes, ","), strings.Join(sel.ProxyTags, ","), sortedVars(vars), cp.ID, cp.Group, cp.Name)
	h.cacheMu.Lock()
	if v, ok := h.scopeMemo[memo]; ok {
		h.cacheMu.Unlock()
		return v
	}
	h.cacheMu.Unlock()
	b, err := h.buildBundle(cp, sel, vars, ver)
	if err != nil {
		return nil
	}
	all := map[string]string{}
	for k, v := range vars {
		all[k] = v
	}
	for k, v := range builtinVars(&cp) {
		all[k] = v
	}
	res, err := ResolveFiles(b.files, all)
	if err != nil {
		return nil
	}
	out := scopeHashesFromFiles(res)
	h.cacheMu.Lock()
	if len(h.scopeMemo) > 1024 {
		h.scopeMemo = map[string]map[string]string{}
	}
	h.scopeMemo[memo] = out
	h.cacheMu.Unlock()
	return out
}
