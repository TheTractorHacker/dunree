//go:build windows && !amd64

package sshprox

import "embed"

/*
Binary embedding for Windows builds other than AMD64 (arm64, 386)

Same as embed_windows_amd64.go: Windows uses wintty (pure Go SSH terminal)
instead of a gotty binary, on every CPU architecture. Added for Dunree so
that windows/arm64 builds.
*/
var (
	//go:embed gotty/LICENSE
	gotty embed.FS
)

// UseWinTTY indicates whether this platform should use wintty
// instead of the gotty binary
const UseWinTTY = true
