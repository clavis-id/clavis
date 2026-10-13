// Package version reports which build of Clavis is running.
//
// The information comes from the metadata the Go toolchain embeds in every
// binary, so no linker flags are required. When Clavis is embedded as a
// library, the version is taken from the host program's dependency list.
package version

import (
	"runtime/debug"
)

// ModulePath is the import path of the Clavis module.
const ModulePath = "clavisid.org/clavis"

// unknown is reported when the build carries no version information.
const unknown = "(devel)"

// Info describes a build of Clavis.
type Info struct {
	// Version is the module version, for example "v0.1.0", a pseudo-version,
	// or "(devel)" when it cannot be determined.
	Version string
	// Commit is the VCS revision the binary was built from, if known.
	Commit string
	// Modified reports whether the working tree had uncommitted changes.
	Modified bool
	// GoVersion is the Go toolchain version used for the build.
	GoVersion string
}

// Get returns the build information of the running program.
func Get() Info {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Info{Version: unknown}
	}
	return fromBuildInfo(bi)
}

// fromBuildInfo extracts Clavis build information from bi.
func fromBuildInfo(bi *debug.BuildInfo) Info {
	info := Info{Version: unknown, GoVersion: bi.GoVersion}

	if bi.Main.Path == ModulePath {
		info.Version = normalize(bi.Main.Version)
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Commit = s.Value
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
		return info
	}

	for _, dep := range bi.Deps {
		if dep.Path != ModulePath {
			continue
		}
		if dep.Replace != nil {
			dep = dep.Replace
		}
		info.Version = normalize(dep.Version)
		break
	}
	return info
}

// normalize maps the empty version to the conventional development marker.
func normalize(v string) string {
	if v == "" {
		return unknown
	}
	return v
}
