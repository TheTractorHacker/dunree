// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// betaFixture is an install that runs the first Dunree version, as PRODUCT_VERSION gives it.
func betaFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.build(func(c *Config) { c.CurrentVersion = "1.0.0-beta.1" })
	return f
}

// forkRelease is a release of the fork Dunree comes from, as its release tooling made them:
// a v3.x tag, its own file names and its own signed header, signed with the same key.
func forkRelease(f *fixture, tag string, pre bool) fakeRelease {
	r := f.release(tag, pre, time.Hour, "FORK-BINARY")
	r.NoBinary = true
	r.ArchAssets = []string{"zoraxy_linux_amd64", "zoraxy_linux_arm64"}         // legacy-compat
	r.HeaderLine = "# zoraxy-release tag=" + tag + " build=4000 upstream=3.3.6" // legacy-compat
	return r
}

// The release source can still be the repository of that fork (UPDATE_REPO). Whatever it
// publishes, a Dunree install is never offered it and never installs it.
func TestForkReleasesAreNotOffered(t *testing.T) {
	for _, ch := range []string{ChannelStable, ChannelBeta} {
		f := betaFixture(t)
		must(t, f.m.SetChannel(ch))
		f.gh.set(forkRelease(f, "v3.3.6-rc9.40", false), forkRelease(f, "v3.3.7", false), forkRelease(f, "v4.0.0-rc.1", true))
		res, err := f.m.Check(context.Background(), true)
		must(t, err)
		if res.UpdateAvailable || res.Latest != nil {
			t.Fatalf("%s: a fork release is on offer: %+v", ch, res)
		}
		if !strings.Contains(res.Reason, "no Dunree release") || !strings.Contains(res.Reason, "o/r") || !strings.Contains(res.Reason, "3 release(s) of another product") {
			t.Errorf("%s: reason %q", ch, res.Reason)
		}
		if res.Current.Version != "1.0.0-beta.1" || res.AssetName != "dunree_linux_amd64" {
			t.Errorf("%s: current %+v asset %s", ch, res.Current, res.AssetName)
		}
		err = f.m.RunApp(context.Background(), RunOptions{})
		if err == nil || !strings.Contains(err.Error(), "nothing to install") {
			t.Fatalf("%s: RunApp: %v", ch, err)
		}
		if f.readExe() != oldBinary || f.restartCount() != 0 {
			t.Errorf("%s: the program file was touched", ch)
		}
		for _, r := range []string{"v3.3.6-rc9.40", "v3.3.7", "v4.0.0-rc.1"} {
			if f.gh.hit("/dl/"+r+"/"+SumsAsset) != 0 || f.gh.hit("/dl/"+r+"/zoraxy_linux_amd64") != 0 { // legacy-compat
				t.Errorf("%s: something of %s was downloaded", ch, r)
			}
		}
		f.unbusy()
		// the page gets an answer, not an error, and the read-only state says "no update"
		rec := call(f.m.HandleCheck, "GET", "/check?force=true", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HandleCheck %d %s", ch, rec.Code, rec.Body.String())
		}
		var body struct {
			Result map[string]any `json:"result"`
		}
		must(t, json.Unmarshal(rec.Body.Bytes(), &body))
		if _, has := body.Result["latest"]; has || body.Result["update_available"] != false {
			t.Errorf("%s: answer %s", ch, rec.Body.String())
		}
		if st := f.m.CachedState(); st.UpdateAvailable || st.Latest != "" || st.Current != "1.0.0-beta.1" {
			t.Errorf("%s: cached state %+v", ch, st)
		}
	}
}

// A release that carries Dunree file names but the signed header of the fork (same key) is
// offered by the list and then refused at the header, before the program file is fetched.
func TestForkHeaderUnderDunreeNamesIsRefused(t *testing.T) {
	f := betaFixture(t)
	r := f.release("v3.3.7", false, time.Hour, "FORK-BINARY")
	r.HeaderLine = "# zoraxy-release tag=v3.3.7 build=4000 upstream=3.3.6" // legacy-compat
	f.gh.set(r)
	f.smoke = func(context.Context, string) (string, error) { return "Dunree - Version 3.3.7", nil }
	err := f.m.RunApp(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "not a Dunree release") {
		t.Fatalf("got %v", err)
	}
	if f.readExe() != oldBinary || f.gh.hit("/dl/v3.3.7/"+testAsset) != 0 {
		t.Error("the program file was fetched or replaced")
	}
}

// Pre-releases are ordered: beta.1 (running) < beta.2 < beta.10 < rc.1 < 1.0.0.
func TestPrereleaseOrderThroughTheManager(t *testing.T) {
	f := betaFixture(t)
	must(t, f.m.SetChannel(ChannelBeta))
	check := func(wantLatest string, wantUpdate bool, rels ...fakeRelease) {
		t.Helper()
		f.gh.set(rels...)
		res, err := f.m.Check(context.Background(), true)
		must(t, err)
		if res.Latest == nil || res.Latest.Tag != wantLatest || res.UpdateAvailable != wantUpdate {
			t.Fatalf("want latest %s update=%v, got %+v (%s)", wantLatest, wantUpdate, res.Latest, res.Reason)
		}
	}
	rel := func(tag string, pre bool) fakeRelease { return f.release(tag, pre, time.Hour, "BIN-"+tag) }
	// the release of the running version is not an update, however it is dated
	check("v1.0.0-beta.1", false, rel("v1.0.0-beta.1", true))
	if res, _ := f.m.Check(context.Background(), true); !strings.Contains(res.Reason, "running the latest") {
		t.Errorf("reason: %q", res.Reason)
	}
	check("v1.0.0-beta.2", true, rel("v1.0.0-beta.1", true), rel("v1.0.0-beta.2", true))
	// beta.10 is newer than beta.2 and beta.9 (numbers, not text), in whatever order the list is
	check("v1.0.0-beta.10", true, rel("v1.0.0-beta.10", true), rel("v1.0.0-beta.9", true), rel("v1.0.0-beta.2", true))
	check("v1.0.0-rc.1", true, rel("v1.0.0-beta.10", true), rel("v1.0.0-rc.1", true))
	check("v1.0.0", true, rel("v1.0.0", false), rel("v1.0.0-rc.1", true), rel("v1.0.0-beta.10", true))
	// an older pre-release published later does not win
	late := rel("v1.0.0-beta.2", true)
	late.Published = fixtureEpoch.Add(24 * time.Hour)
	check("v1.0.0", true, late, rel("v1.0.0", false))

	// stable channel: a pre-release is not offered, also when its GitHub flag was forgotten
	must(t, f.m.SetChannel(ChannelStable))
	f.gh.set(rel("v1.0.0-beta.2", true), rel("v1.0.0-rc.1", false))
	res, err := f.m.Check(context.Background(), true)
	must(t, err)
	if res.UpdateAvailable || res.Latest != nil || !strings.Contains(res.Reason, "no Dunree release on the stable channel") {
		t.Fatalf("stable with pre-releases only: %+v", res)
	}
	check("v1.0.0", true, rel("v1.0.0-rc.1", false), rel("v1.0.0", false))

	// a running final release is not offered its own release candidates or betas
	f.build(func(c *Config) { c.CurrentVersion = "1.0.0" })
	must(t, f.m.SetChannel(ChannelBeta))
	f.gh.set(rel("v1.0.0-rc.3", true), rel("v1.0.0-beta.10", true))
	res, err = f.m.Check(context.Background(), true)
	must(t, err)
	if res.UpdateAvailable || !strings.Contains(res.Reason, "older than the running build") {
		t.Fatalf("pre-releases of the running version offered: %+v", res)
	}
}

// From beta.1 to beta.2: installed, recorded as a Dunree install, and then the latest.
func TestUpdateBetweenPrereleases(t *testing.T) {
	f := betaFixture(t)
	must(t, f.m.SetChannel(ChannelBeta))
	f.gh.set(f.release("v1.0.0-beta.2", true, time.Hour, "BETA-2"))
	// a program that reports another pre-release of the same version is not the release
	f.smoke = func(context.Context, string) (string, error) {
		return "Dunree - Version 1.0.0-beta.20 (based on Zoraxy 3.3.6)", nil // legacy-compat: the base is named
	}
	if err := f.m.RunApp(context.Background(), RunOptions{}); err == nil || !strings.Contains(err.Error(), "unexpected version output") {
		t.Fatalf("a program of another version passed the check: %v", err)
	}
	f.smoke = func(context.Context, string) (string, error) { return "Dunree - Version 1.0.0", nil }
	if err := f.m.RunApp(context.Background(), RunOptions{}); err == nil || !strings.Contains(err.Error(), "unexpected version output") {
		t.Fatalf("the final version passed for the pre-release: %v", err)
	}
	if f.readExe() != oldBinary {
		t.Fatal("the program file was replaced by a release that failed the check")
	}
	f.smoke = nil
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	if f.readExe() != "BETA-2" {
		t.Fatalf("not installed: %q", f.readExe())
	}
	inst := f.m.st.installed()
	if inst == nil || inst.Product != "dunree" || inst.Tag != "v1.0.0-beta.2" || inst.Build != 1000 {
		t.Fatalf("install record: %+v", inst)
	}
	f.m.MarkHealthy()
	f.unbusy()
	f.build(func(c *Config) { c.CurrentVersion = "1.0.0-beta.2" }) // the new program after the restart
	must(t, f.m.SetChannel(ChannelBeta))
	res, err := f.m.Check(context.Background(), true)
	must(t, err)
	if res.UpdateAvailable || !res.Current.Known || res.Current.Tag != "v1.0.0-beta.2" {
		t.Fatalf("after the update: %+v", res)
	}
}

// installed.json left behind by the updater of the fork (no product field) is not trusted,
// even when its checksum happens to describe the running file: the running build is then
// the version the program was compiled with, and its build number does not block Dunree releases.
func TestInstallRecordOfAnotherProductIsIgnored(t *testing.T) {
	f := betaFixture(t)
	sum, err := fileSHA256(f.exe)
	must(t, err)
	must(t, os.MkdirAll(f.m.st.path(""), 0o755))
	must(t, os.WriteFile(f.m.st.path("installed.json"),
		[]byte(`{"tag":"v3.3.6-rc9.40","published":"2026-10-01T00:00:00Z","sha256":"`+sum+`","build":1790000000}`), 0o600))
	must(t, f.m.SetChannel(ChannelBeta))
	f.gh.set(f.release("v1.0.0-beta.2", true, time.Hour, "BETA-2"))
	res, err := f.m.Check(context.Background(), true)
	must(t, err)
	if res.Current.Known || res.Current.Tag != "" || res.Current.Version != "1.0.0-beta.1" || !res.UpdateAvailable {
		t.Fatalf("the record of the fork was trusted: %+v", res)
	}
	// its build number (far above 1000) must not make the Dunree release a "downgrade"
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	if f.readExe() != "BETA-2" {
		t.Fatal("not installed")
	}
	if inst := f.m.st.installed(); inst == nil || inst.Product != "dunree" || inst.Previous != nil {
		t.Fatalf("install record: %+v", inst)
	}
}
