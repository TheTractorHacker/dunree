// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package apitoken

import (
	"net/http/httptest"
	"testing"
)

func TestDenyNamesTheDunreeRealm(t *testing.T) {
	w := httptest.NewRecorder()
	deny(w, 401)
	if g := w.Header().Get("WWW-Authenticate"); g != `Bearer realm="dunree"` {
		t.Fatalf("realm: %q", g)
	}
}
