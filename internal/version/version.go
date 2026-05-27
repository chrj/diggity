package version

import "runtime/debug"

// Version is overridden at build time with -ldflags "-X .../version.Version=...".
var Version = "dev"

// String returns a printable version string.
func String() string {
	if Version != "dev" {
		return "diggity " + Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return "diggity " + v
		}
	}
	return "diggity dev"
}
