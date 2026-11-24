# Security policy

This is the security policy of **Dunree**, published by Foley IT.

## Reporting a vulnerability

Please report a vulnerability **privately**. Do not open a public issue, pull request or discussion for it.

**Security contact:** `SECURITY-CONTACT-NOT-SET`

<!-- OWNER: set the security contact before the first public release. Replace the placeholder above with a
     monitored address (for example a security@ mailbox) or the address of a private reporting form, set the
     same value as SecurityContact in src/mod/brand/brand.go, and remove this comment.
     The test TestSecurityPolicyNamesAContact in src/brandweb_test.go reports whether the placeholder is still there. -->

Until a contact is set here, send the report to Foley IT through the channel you got Dunree from, and mark it as a security report.

Please include:

- the Dunree version (*System > Utilities > About Dunree*, or `dunree -version`) and how it is run (binary, systemd, Docker);
- what an attacker can do, and what they need for it (network position, an account, a setting that must be on);
- the steps to reproduce it, with requests or configuration where possible;
- whether you believe the problem is also in Zoraxy, the project Dunree is based on.

## What to expect

- An answer that the report arrived, within 5 working days.
- An assessment and, if we confirm it, a plan with a date, within 15 working days.
- A fix in a signed release, and a note in `CHANGELOG.md` that credits you unless you ask us not to.
- We ask you not to publish details before a fixed release is available, or before 90 days have passed, whichever comes first.

Reports written by a tool or a language model are welcome when a person has reproduced the problem first. Reports without steps that reproduce the problem are closed.

## Supported versions

| Version | Supported |
|---|---|
| Dunree 1.0 (beta and later) | yes, the latest release |
| Zoraxy, and builds named `v3.3.6-fork.N` | no. Move to Dunree, see `docs/migrating-from-zoraxy.md`. |

## Scope

In scope: the Dunree program, its admin interface and API, the default pages it shows to visitors, the plugin SDK and the release and add-on signing tools in this repository.

Not in scope: plugins and add-ons of other publishers, a store index run by someone else, and services Dunree can be connected to (identity providers, CAPTCHA providers, CrowdSec, ACME authorities).

## Zoraxy

Dunree is based on Zoraxy v3.3.6 by tobychui and imuslab and is a separate project. **Do not report Dunree vulnerabilities to the Zoraxy project.** If a problem is in code that Zoraxy also has, tell us; reporting it to the Zoraxy project is then up to you and follows their policy.

## Verifying a release

Official releases are signed (ed25519 signature of `SHA256SUMS`). The updater in the admin interface refuses a release whose signature or checksum does not match. The public key is `src/mod/updater/release_pubkey.pem`.
