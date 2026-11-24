# Contributing to Dunree

Thank you for helping. Dunree is published by Foley IT under AGPL-3.0 and is based on Zoraxy v3.3.6 by tobychui and imuslab.

## Before you start

- **Bugs and ideas:** open an issue in the Dunree project. Please do not open Dunree issues in the Zoraxy project and do not tag its maintainers.
- **Security problems:** not in an issue. See [`SECURITY.md`](SECURITY.md).
- **Large changes:** describe the idea in an issue first, so that nobody builds something that cannot be merged.

The address of the Dunree repository is not final yet (beta). Use the place you got the source from.

## Rules for a change

These rules exist because people run Dunree in front of their services and upgrade it in place.

1. **Existing installs keep working.** A change must not alter what an existing install does without the administrator choosing it. New behaviour is off, or log-only, by default.
2. **Names other programs see keep working.** Headers, paths, cookies, metric names, environment variables, file names and API fields that are renamed keep a legacy path. The policy is in `docs/rebrand/plan.md` and `tools/rebrand/policy.json`.
3. **Every change has an automated test.** Go tests next to the code; for the admin interface a scenario in `tools/ui-smoke`.
4. **Every change is written down** in `docs/ux/changes.md`, with a "Known limits" note that says honestly what it does not do.
5. **Plugins fail open** unless the administrator chose otherwise. Releases stay signed.
6. **No call to another service by default.** An address Dunree contacts is a setting, and nothing is fetched until an administrator turns it on. `src/mod/upstreamguard` checks that no address of the Zoraxy project is contacted.
7. **Text of the admin interface** follows `docs/ux/terminology.md`. After a change of text run `python3 tools/i18n/extract.py` and `python3 tools/i18n/extract.py --check`.

## Build and test

Go 1.26 or newer.

```bash
cd src
go build ./...
go vet ./...
go test -p 1 ./...
```

Admin interface (needs Python with Playwright and Chromium):

```bash
PY=/path/to/python PORT=24100 tools/ui-smoke/run.sh --out /tmp/shots
```

Do not edit `src/web` while the smoke test runs. More detail, including the end-to-end suites and how a release is built and signed, is in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Style

- Go: `gofmt`, short functions, comments that say why.
- Admin interface: use the components in `docs/ux/components.md` and the design rules in `docs/ux/design-v2.md`. Light and dark theme, and a phone-sized window, must work.
- Brand: use the files in `brand/` as they are; the rules are in `brand/README.md`.
- Plain language in texts and documents. Short sentences. Say what a thing does.

## Licence of your contribution

Dunree is licensed under AGPL-3.0. By sending a change you agree that it is published under that licence, and you confirm that you have the right to send it (it is your own work, or its licence allows it).

- Sign your commits off (`git commit -s`), which states the [Developer Certificate of Origin](https://developercertificate.org/).
- New files get a Foley IT or contributor copyright line. **Do not remove or change the copyright and licence headers of the original authors** (tobychui, imuslab and the Zoraxy contributors), `LICENSE`, `NOTICE` or `THIRD_PARTY_NOTICES.md`.
- Code taken from another project must have a licence that is compatible with AGPL-3.0 (MIT, BSD, Apache-2.0, GPL-3.0), and must be listed in `THIRD_PARTY_NOTICES.md`.
- Do not present new work as the work of the Zoraxy authors, and do not present their work as yours.
