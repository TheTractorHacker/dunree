## Other checks of the final audit (2026-11-24)

### No default call to an upstream host

* `src/mod/upstreamguard` (`TestNoDefaultCallToUpstreamHosts`) scans every Go and web source that is compiled or
  embedded into Dunree for `aroz.org`, `imuslab.com`, `aroz-online`, `github.com/tobychui`, `githubusercontent.com/tobychui`,
  `tobychui.github.io` and `zoraxydocker`. Outside comments and credit text exactly one line is allowed:
  `LegacyZoraxyStoreIndexURL` in `mod/plugins/store_sources.go`, which is only written into the settings of an install that
  already used upstream's store before it ran Dunree (`TestExistingInstallKeepsItsStoreSourceOnce`); a new install
  contacts no store at all (`TestNoStoreAndNoConnectionByDefault`). The two mDNS entries of its allow list were removed
  by this audit: the TXT record now says vendor `Foley IT`, domain `dunree.local`.
* Every external address in a Go string literal of the product (non-test) code was listed. Besides the store entry above
  they are services the administrator configures or turns on (CAPTCHA providers, notification channels, the AI
  assistant, `checkip.amazonaws.com` for the public-address check, the GeoIP lists on jsDelivr) and the updater's
  `api.github.com`, which asks the repository of the policy variable `UPDATE_REPO` (`TheTractorHacker/zoraxy`, the
  release source of this fork, not upstream) only when an administrator opens the update page or starts a check;
  `-update_repo` changes it. None of them is a host of tobychui or imuslab.
* The one test that reached an upstream host on the network (`netutils_test.go`, traceroute to `imuslab.com`) now
  uses `example.com`.

### Build, vet and tests (cwd `src`, through `~/capped.sh`, `GOTMPDIR=$HOME/.cache/go-tmp`)

| Command | Result |
|---|---|
| `go vet ./...` | pass |
| `GOOS=windows go build ./...` | pass |
| `GOOS=darwin go build ./...` | pass |
| `go test -p 1 ./...` | pass (85 packages ok, exit 0) |
| `python3 tools/rebrand/test_rename.py` (21 tests, incl. `test_no_leftover_in_the_audit`, `test_notice_is_accurate`) | pass |
| `python3 docker/test_entrypoint.py`, `python3 contrib/crowdsec/test_crowdsec_setup.py` | pass |
| UI smoke `tools/ui-smoke/run.sh` | pass, "OK, screenshots in ..." (PORT 24631). The first run failed once in the brand check: on this instance, which counts as an existing install, the App Store loaded plugin icons of the migrated Zoraxy community store from GitHub. `brand_smoke.py` now excludes exactly those requests while that third-party source is configured |

### Module path and the rename tool

* `src/go.mod` says `module github.com/TheTractorHacker/dunree`, which is `MODULE_ROOT` in `tools/rebrand/policy.json`. The
  secondary modules are `MODULE_ROOT/docs`, `/benchmark`, `/tools/...`, the `tools/nt6.1_go_mod` copies use
  `MODULE_ROOT`, the example plugins use `example.com/dunree/<name>`. No `.go` or `go.mod` file outside the frozen
  SDK fixtures imports `imuslab.com/zoraxy` (`Repo.test_module_root_matches_policy`).
* `python3 tools/rebrand/rename.py --dry-run` (the default mode) on the finished tree: `Would change 0 files`, no
  renames pending (`Repo.test_pass_is_fully_applied` runs `--check`).

### Licence and notices

* `LICENSE` is byte-identical to the committed file (sha256 `8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef`,
  only commit "Create LICENSE"); `THIRD_PARTY_NOTICES.md` and `third_party/` are unchanged.
* `NOTICE` exists and says: Dunree, Copyright (C) 2026 Foley IT, AGPL-3.0; based on Zoraxy v3.3.6, Copyright (C)
  2021-2026 tobychui and imuslab and the Zoraxy contributors, with the original project's address; "a modified,
  independent derivative", "not affiliated with, sponsored by or endorsed by tobychui, imuslab or the Zoraxy
  contributors"; the Zoraxy authors "did not write, review or approve" the Dunree parts. `src/web/legal/NOTICE.txt`, the
  copy the About page serves, is identical (`Repo.test_notice_is_accurate`).
* Every file of the committed tree that had a `Copyright (c) ... tobychui` or `Author: tobychui` header still names
  tobychui; `tobychui` occurs more often than in the committed tree (301 there): credits were added, none removed.
