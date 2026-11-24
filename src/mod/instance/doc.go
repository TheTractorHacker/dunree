// Package instance answers "who else is running Dunree on this machine, and why is it stuck?".
//
// It exists because of a real incident: an admin pressed Ctrl+Z in a terminal running start.sh.
// SIGTSTP froze Dunree, which kept its listening sockets, so the kernel queued connections that
// nobody accepted. A second copy started by systemd then blocked forever on the database lock
// held by the frozen one, and nothing said so.
//
// Contents:
//   - lock.go / proc.go / net.go: pure parsers for /proc text (unit tested with fixtures)
//   - instance_linux.go: the Linux file system readers built on those parsers (stubs elsewhere)
//   - doctor.go: the read-only report behind "dunree -doctor"
//   - notify.go: sd_notify without a dependency (READY=1, STATUS=, STOPPING=1)
package instance
