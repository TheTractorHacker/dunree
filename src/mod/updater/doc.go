// Package updater implements the in-app "Update" page backend of Dunree:
// release discovery on GitHub, ed25519 + SHA-256 verification, backup,
// atomic binary replacement, restart and automatic rollback.
//
// # Security / behaviour contract
//
//   - No network access happens unless an administrator opens the Update page
//     or clicks a button. There is no automatic update (a future "auto update"
//     setting would be off by default and is deliberately not implemented).
//   - A downloaded binary is only installed if SHA256SUMS carries a valid raw
//     ed25519 signature (SHA256SUMS.sig) made with the public key embedded in
//     release_pubkey.pem AND the binary's SHA-256 matches its SHA256SUMS line.
//   - Updates are forward-only (see CompareReleases). Rolling back is a
//     separate, explicit operation that restores the saved previous binary.
//
// # Version ordering rule
//
// Dunree has its own version line, which starts at v1.0.0-beta.1 and is not the
// version of the code base it is derived from. Release tags are Semantic
// Versioning tags, v<major>.<minor>.<patch>[-<pre-release>] (v1.0.0-beta.1 <
// v1.0.0-beta.2 < v1.0.0-rc.1 < v1.0.0 < v1.0.1), and are ordered by that
// precedence alone (CompareTags). The running build is the PRODUCT_VERSION the
// program was compiled with, or the tag in <conf>/updater/installed.json when
// the updater installed the running file (trusted only while the SHA-256 of the
// executable still matches and the record says product "dunree").
//
// Only Dunree releases are considered. A release counts as one when it carries
// dunree_<os>_<arch> program files, and it is installed only when the signed
// first line of SHA256SUMS reads "# dunree-release product=dunree tag=<tag>
// build=<n> ...". The releases of the fork Dunree comes from carry v3.x tags,
// other file names and another header: they are skipped in the list and, since
// they are signed with the same key, refused by name at the header. A tag with
// a pre-release part is never offered on the stable channel.
//
// There is no in-app path from a build of that fork to Dunree: its updater
// does not know the Dunree file names, header or version line. Such an install
// is switched by replacing the program file (the migration guide in docs/).
//
// # Restart strategy
//
// After the new binary is renamed over the old one the process runs its normal
// shutdown sequence and then re-executes the new binary in place with
// syscall.Exec (same PID, same arguments and environment). That keeps a
// systemd MainPID valid whatever the Restart= policy of the unit is. If exec
// fails the process exits with status 75 so that a supervisor with
// Restart=on-failure/always brings the new binary up.
//
// # Rollback
//
// A pending-update marker (<conf>/updater/pending.json) is written before the
// restart. The new process must reach "healthy" (management HTTP listener up
// and proxy router initialised) within HealthyTimeout. Two independent layers
// restore the previous binary otherwise: an in-process guard started at the
// very beginning of main (covers hangs and crash loops: the start attempt
// counter in the marker is bumped on every start), and an out-of-process
// watchdog child (the old binary run with -updater_watchdog) which survives
// the in-place exec but is killed by systemd's cgroup cleanup if the unit is
// stopped or restarted.
package updater
