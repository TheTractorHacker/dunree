package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseTag(t *testing.T) {
	cases := []struct {
		in    string
		want  Tag
		isErr bool
	}{
		{"v1.0.0", Tag{Major: 1}, false},
		{"1.0.0-beta.1", Tag{Major: 1, Pre: []string{"beta", "1"}}, false}, // PRODUCT_VERSION has no leading v
		{"v1.0.0-beta.1", Tag{Major: 1, Pre: []string{"beta", "1"}}, false},
		{"v1.2.3-rc.2", Tag{Major: 1, Minor: 2, Patch: 3, Pre: []string{"rc", "2"}}, false},
		{"v10.20.30", Tag{Major: 10, Minor: 20, Patch: 30}, false},
		{" v1.0.1 ", Tag{Major: 1, Patch: 1}, false},
		{"nightly", Tag{}, true},
		{"v1.0", Tag{}, true},
		{"v1.0.0.1", Tag{}, true}, // four numbers: the tag form of the earlier fork
		{"v1.0.0-", Tag{}, true},
		{"v1.0.0-beta..1", Tag{}, true},
		{"v1.0.0+build5", Tag{}, true},
		{"v01.0.0", Tag{}, true},
		{"v1.0.0-beta_1", Tag{}, true},
		// Semantic Versioning 9: a numeric identifier has no leading zero. beta.01 would have the
		// same precedence as beta.1 under another tag, so two releases could not be told apart.
		{"v1.0.0-beta.01", Tag{}, true},
		{"v1.0.0-00", Tag{}, true},
		{"v1.0.0-beta.0", Tag{Major: 1, Pre: []string{"beta", "0"}}, false},
		{"v1.0.0-0a.1", Tag{Major: 1, Pre: []string{"0a", "1"}}, false}, // alphanumeric: a leading 0 is fine
		{"v1.0.0-rc-1", Tag{Major: 1, Pre: []string{"rc-1"}}, false},
	}
	for _, c := range cases {
		got, err := ParseTag(c.in)
		if (err != nil) != c.isErr {
			t.Fatalf("%s: err=%v", c.in, err)
		}
		if err == nil {
			got.Raw = ""
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s: got %+v want %+v", c.in, got, c.want)
			}
		}
	}
	if tg, _ := ParseTag("v1.0.0-beta.1"); tg.Version() != "1.0.0-beta.1" || tg.BaseVersion() != "1.0.0" || !tg.IsPrerelease() {
		t.Errorf("Version/BaseVersion/IsPrerelease: %+v", tg)
	}
	if tg, _ := ParseTag("v2.1.0"); tg.Version() != "2.1.0" || tg.IsPrerelease() {
		t.Errorf("final release: %+v", tg)
	}
}

func bid(t *testing.T, tag string, age time.Duration) BuildID {
	tg, err := ParseTag(tag)
	if err != nil {
		t.Fatal(err)
	}
	b := BuildID{Tag: tg}
	if age >= 0 {
		b.Published = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Add(-age)
	}
	return b
}

// The whole order, oldest first. Every pair is checked in both directions.
func TestVersionOrder(t *testing.T) {
	order := []string{
		"v0.9.9",
		"v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta",
		"v1.0.0-beta", "v1.0.0-beta.1", "v1.0.0-beta.2", "v1.0.0-beta.10", "v1.0.0-beta.11",
		"v1.0.0-rc.1", "v1.0.0-rc.2",
		"v1.0.0",
		"v1.0.1-beta.1", "v1.0.1",
		"v1.1.0-rc.1", "v1.1.0", "v1.10.0",
		"v2.0.0-beta.1", "v2.0.0",
	}
	for i, a := range order {
		for j, b := range order {
			ta, err := ParseTag(a)
			must(t, err)
			tb, err := ParseTag(b)
			must(t, err)
			want := sign(i - j)
			if got := CompareTags(ta, tb); got != want {
				t.Errorf("CompareTags(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
	// numbers are compared as numbers, also long ones and ones with leading zeros
	for _, c := range []struct {
		a, b string
		want int
	}{{"9", "10", -1}, {"10", "9", 1}, {"007", "7", 0}, {"99999999999999999999", "100000000000000000000", -1}, {"1", "rc", -1}, {"rc", "1", 1}, {"beta", "rc", -1}, {"rc", "rc", 0}} {
		if got := compareIdent(c.a, c.b); got != c.want {
			t.Errorf("compareIdent(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareReleases(t *testing.T) {
	day := 24 * time.Hour
	// the time a release was published does not take part in the order
	if CompareReleases(bid(t, "v1.0.0-beta.2", 100*day), bid(t, "v1.0.0-beta.1", 0)) != 1 {
		t.Error("an older published date must not make beta.2 older than beta.1")
	}
	if CompareReleases(bid(t, "v1.0.0", day), bid(t, "v1.0.0", 5*day)) != 0 {
		t.Error("the same version published at another time is the same version")
	}
	// the running build (no date): a release of its own version is not an update
	run := bid(t, "1.0.0-beta.1", -1)
	if CompareReleases(bid(t, "v1.0.0-beta.1", day), run) != 0 {
		t.Error("the release of the running version must compare equal")
	}
	if CompareReleases(bid(t, "v1.0.0-beta.2", day), run) != 1 || CompareReleases(bid(t, "v1.0.0", day), run) != 1 {
		t.Error("the next pre-release and the final release are newer than the running pre-release")
	}
	if CompareReleases(bid(t, "v0.9.0", day), run) != -1 {
		t.Error("a lower version is older")
	}
}

func dunreeRel(tag string, pre bool) Release {
	return Release{Tag: tag, Prerelease: pre, Assets: []Asset{{Name: "dunree_linux_amd64"}, {Name: SumsAsset}, {Name: SigAsset}}}
}

func TestLatestForChannel(t *testing.T) {
	rels := []Release{
		dunreeRel("v1.0.0", false),
		dunreeRel("v1.1.0-beta.2", true),
		dunreeRel("v1.1.0-rc.1", false), // the pre-release flag was forgotten on GitHub
		dunreeRel("garbage", false),
		dunreeRel("v0.9.0", false),
	}
	s, err := LatestForChannel(rels, ChannelStable)
	if err != nil || s.Tag != "v1.0.0" {
		t.Fatalf("stable: %+v %v", s, err)
	}
	b, err := LatestForChannel(rels, ChannelBeta)
	if err != nil || b.Tag != "v1.1.0-rc.1" {
		t.Fatalf("beta: %+v %v", b, err)
	}
	_, err = LatestForChannel([]Release{dunreeRel("v1.0.0-beta.1", true)}, ChannelStable)
	var none *ErrNoRelease
	if !errors.As(err, &none) || none.Other != 0 {
		t.Fatalf("only pre-releases on stable: %v", err)
	}
}

// The release source may still be the repository of the fork Dunree comes from (policy variable
// UPDATE_REPO). Its releases have higher version numbers than Dunree's and must never be offered.
func TestForkReleasesAreNeverNewer(t *testing.T) {
	fork := func(tag string, pre bool) Release { // legacy-compat: the file names of those releases
		return Release{Tag: tag, Prerelease: pre, Published: time.Now(), Assets: []Asset{
			{Name: "zoraxy_linux_amd64"}, {Name: "zoraxy_linux_arm64"}, {Name: "crowdsec-setup.sh"}, {Name: SumsAsset}, {Name: SigAsset}}} // legacy-compat
	}
	forkOnly := []Release{fork("v3.3.6-rc9.40", false), fork("v3.3.7", false), fork("v3.3.5-rc5-grpcfix.1", true), fork("v4.0.0", false)}
	for _, ch := range []string{ChannelStable, ChannelBeta} {
		_, err := LatestForChannel(forkOnly, ch)
		var none *ErrNoRelease
		if !errors.As(err, &none) || none.Other != len(forkOnly) {
			t.Fatalf("%s: fork releases must not be candidates: %v", ch, err)
		}
	}
	mixed := append([]Release{dunreeRel("v1.0.0-beta.2", true), dunreeRel("v1.0.0", false)}, forkOnly...)
	if r, err := LatestForChannel(mixed, ChannelBeta); err != nil || r.Tag != "v1.0.0" {
		t.Fatalf("mixed source: %+v %v", r, err)
	}
	for _, r := range forkOnly {
		if IsDunreeRelease(r) {
			t.Errorf("%s counted as a Dunree release", r.Tag)
		}
	}
	// names that only look like program files do not make a release a Dunree release
	for _, n := range []string{"dunree_1.0.0_linux_amd64.tar.gz", "dunree_1.0.0_amd64.deb", "dunree-setup.exe", "dunree_linux", "xdunree_linux_amd64", "dunree_linux_amd64.sha256", "DUNREE_linux_amd64"} {
		if IsDunreeRelease(Release{Assets: []Asset{{Name: n}}}) {
			t.Errorf("%s alone must not mark a Dunree release", n)
		}
	}
	for _, n := range []string{"dunree_linux_amd64", "dunree_windows_arm64.exe", "dunree_darwin_arm64", "dunree_linux_riscv64"} {
		if !IsDunreeRelease(Release{Assets: []Asset{{Name: n}}}) {
			t.Errorf("%s must mark a Dunree release", n)
		}
	}
}

func TestAssetName(t *testing.T) {
	for _, c := range [][3]string{
		{"linux", "amd64", "dunree_linux_amd64"}, {"linux", "arm64", "dunree_linux_arm64"},
		{"linux", "arm", "dunree_linux_arm"}, {"linux", "386", "dunree_linux_386"},
		{"linux", "riscv64", "dunree_linux_riscv64"}, {"linux", "mipsle", "dunree_linux_mipsle"},
		{"windows", "amd64", "dunree_windows_amd64.exe"}, {"windows", "arm64", "dunree_windows_arm64.exe"},
		{"darwin", "amd64", "dunree_darwin_amd64"}, {"darwin", "arm64", "dunree_darwin_arm64"},
		{"freebsd", "amd64", "dunree_freebsd_amd64"},
	} {
		if got := AssetName(c[0], c[1]); got != c[2] {
			t.Errorf("AssetName(%s,%s)=%s", c[0], c[1], got)
		}
		if !isProgramAsset(c[2]) {
			t.Errorf("%s is not recognised as a program file", c[2])
		}
	}
	// selection is by exact name: the file of another platform, an archive, a package or the
	// file name of the earlier fork is never taken for this platform
	rel := Release{Assets: []Asset{{Name: "dunree_linux_arm64"}, {Name: "dunree_1.0.0_linux_amd64.tar.gz"}, {Name: "dunree_linux_amd64.exe"},
		{Name: "zoraxy_linux_amd64"}, {Name: "dunree_linux_amd64"}}} // legacy-compat
	if a, ok := FindAsset(rel, AssetName("linux", "amd64")); !ok || a.Name != "dunree_linux_amd64" {
		t.Error("FindAsset")
	}
	if _, ok := FindAsset(rel, AssetName("linux", "riscv64")); ok {
		t.Error("FindAsset must not find a missing arch")
	}
	if _, ok := FindAsset(Release{Assets: []Asset{{Name: "zoraxy_linux_amd64"}}}, AssetName("linux", "amd64")); ok { // legacy-compat
		t.Error("the file name of the earlier fork must not be selected")
	}
}

func TestVersionInOutput(t *testing.T) {
	out := "Dunree - Version 1.0.0-beta.1 (based on Zoraxy 3.3.6)" // legacy-compat: the base is named in the output
	if !VersionInOutput(out, "1.0.0-beta.1") {
		t.Error("the version of the program must be found")
	}
	for _, v := range []string{"1.0.0", "1.0.0-beta.10", "1.0.0-beta", "0.0", "beta.1"} {
		if VersionInOutput(out, v) {
			t.Errorf("%q must not pass as the version in %q", v, out)
		}
	}
	// the base version is named in the output: a release of that number must be able to tell
	if !VersionInOutput(out, "3.3.6") {
		t.Log("note: the base version stands as a word in the output")
	}
	if !VersionInOutput("Dunree - Version 1.0.0", "1.0.0") || VersionInOutput("", "1.0.0") {
		t.Error("plain output")
	}
}

func TestEmbeddedPublicKey(t *testing.T) {
	k, err := EmbeddedPublicKey()
	if err != nil || len(k) != ed25519.PublicKeySize {
		t.Fatalf("embedded key: %v", err)
	}
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("binary-bytes")
	sums := sumsFor("dunree_linux_amd64", bin)
	sig := ed25519.Sign(priv, sums)

	if err := VerifySums(pub, sums, sig); err != nil {
		t.Fatalf("good signature rejected: %v", err)
	}
	if VerifySums(otherPub, sums, sig) == nil {
		t.Error("wrong key accepted")
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if VerifySums(pub, sums, bad) == nil {
		t.Error("corrupted signature accepted")
	}
	if VerifySums(pub, append(sums, '\n'), sig) == nil {
		t.Error("tampered SHA256SUMS accepted")
	}
	if VerifySums(pub, sums, sig[:10]) == nil || VerifySums(pub, sums, nil) == nil {
		t.Error("short/missing signature accepted")
	}
	if err := VerifyBinarySum(sums, "dunree_linux_amd64", sha256.Sum256(bin)); err != nil {
		t.Errorf("good binary rejected: %v", err)
	}
	if VerifyBinarySum(sums, "dunree_linux_amd64", sha256.Sum256(append(bin, 'x'))) == nil {
		t.Error("tampered binary accepted")
	}
	if VerifyBinarySum(sums, "dunree_linux_arm64", sha256.Sum256(bin)) == nil {
		t.Error("asset missing from SHA256SUMS accepted")
	}
	dup := append(append([]byte(nil), sums...), sums...)
	if _, err := SumFor(dup, "dunree_linux_amd64"); err == nil {
		t.Error("duplicate entries accepted")
	}
	if _, err := SumFor([]byte("zz  dunree_linux_amd64\n"), "dunree_linux_amd64"); err == nil {
		t.Error("malformed hash accepted")
	}
}

func TestSumsHeader(t *testing.T) {
	line := FormatSumsHeader(SumsHeader{Tag: "v1.0.0-beta.1", Build: 5, Upstream: "3.3.6"})
	if line != "# dunree-release product=dunree tag=v1.0.0-beta.1 build=5 upstream=3.3.6" {
		t.Fatalf("header line: %q", line)
	}
	body := string(sumsFor("dunree_linux_amd64", []byte("b")))
	good := []byte(line + "\n" + body)
	h, err := CheckSumsHeader(good, "v1.0.0-beta.1", 4)
	if err != nil || h.Product != "dunree" || h.Tag != "v1.0.0-beta.1" || h.Build != 5 || h.Upstream != "3.3.6" {
		t.Fatalf("good header: %+v %v", h, err)
	}
	if _, err := SumFor(good, "dunree_linux_amd64"); err != nil {
		t.Fatalf("the header line must not disturb checksum parsing: %v", err)
	}
	// CRLF line ends, another order of the fields and fields this version does not know
	for _, l := range []string{
		line + "\r",
		"# dunree-release tag=v1.0.0-beta.1 upstream=3.3.6 build=5 product=dunree",
		"# dunree-release product=dunree tag=v1.0.0-beta.1 build=5 upstream=3.3.6 channel=beta later",
		"# dunree-release product=dunree tag=v1.0.0-beta.1 build=5",
	} {
		if _, err := CheckSumsHeader([]byte(l+"\n"+body), "v1.0.0-beta.1", 0); err != nil {
			t.Errorf("%q must be accepted: %v", l, err)
		}
	}
	for name, c := range map[string]struct {
		sums      []byte
		tag       string
		installed int
		other     bool // refused as another product
	}{
		"no header":      {[]byte(body), "v1.0.0-beta.1", 0, false},
		"wrong tag":      {good, "v1.0.0", 0, false},
		"build equal":    {good, "v1.0.0-beta.1", 5, false},
		"build lower":    {good, "v1.0.0-beta.1", 6, false},
		"bad build":      {[]byte("# dunree-release product=dunree tag=v1 build=x upstream=1.0.0\n"), "v1", 0, false},
		"missing fields": {[]byte("# dunree-release product=dunree upstream=1.0.0\n"), "v1", 0, false},
		"tag twice":      {[]byte("# dunree-release product=dunree tag=v9.0.0 tag=v1.0.0-beta.1 build=5\n" + body), "v1.0.0-beta.1", 0, false},
		"product twice":  {[]byte("# dunree-release product=other product=dunree tag=v1.0.0-beta.1 build=5\n" + body), "v1.0.0-beta.1", 0, false},
		"no product":     {[]byte("# dunree-release tag=v1.0.0-beta.1 build=5 upstream=3.3.6\n" + body), "v1.0.0-beta.1", 0, true},
		"other product":  {[]byte("# dunree-release product=dunree-enterprise tag=v1.0.0-beta.1 build=5\n" + body), "v1.0.0-beta.1", 0, true},
		"not first line": {[]byte(body + line + "\n"), "v1.0.0-beta.1", 0, false},
		// a release of the earlier fork: signed with the same key, so it must be refused by its header
		"fork header":              {[]byte("# zoraxy-release tag=v3.3.6-rc9.40 build=40 upstream=3.3.6\n" + body), "v3.3.6-rc9.40", 0, true},               // legacy-compat
		"fork header with product": {[]byte("# zoraxy-release tag=v1.0.0-beta.1 build=5 upstream=3.3.6 product=dunree\n" + body), "v1.0.0-beta.1", 0, true}, // legacy-compat
	} {
		_, err := CheckSumsHeader(c.sums, c.tag, c.installed)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if errors.Is(err, ErrOtherProduct) != c.other {
			t.Errorf("%s: ErrOtherProduct=%v, want %v (%v)", name, errors.Is(err, ErrOtherProduct), c.other, err)
		}
	}
	if !strings.HasPrefix(line, sumsHeaderPrefix) || strings.HasPrefix(line, legacySumsHeaderPrefix) {
		t.Error("prefixes")
	}
}
