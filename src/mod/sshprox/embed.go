//go:build !windows && !(linux && (amd64 || 386 || arm || arm64)) && !(darwin && amd64)

// Every platform without an embedded gotty binary (linux/mipsle, linux/riscv64, darwin/arm64,
// the BSDs, ...). The condition is the complement of the embed_<os>_<arch>.go files and of
// embed_windows*.go, so that a new target compiles without a new file (Dunree change).

package sshprox

import "embed"

/*
Binary embedding

Make sure when compile, gotty binary exists in static.gotty
*/
var (
	//go:embed gotty/LICENSE
	gotty embed.FS
)

// UseWinTTY indicates whether this platform should use wintty
// instead of the gotty binary
const UseWinTTY = false
