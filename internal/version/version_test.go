package version

import (
	"runtime/debug"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFromBuildInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		bi   *debug.BuildInfo
		want Info
	}{
		{
			name: "main module with VCS metadata",
			bi: &debug.BuildInfo{
				GoVersion: "go1.27.2",
				Main:      debug.Module{Path: ModulePath, Version: "v0.1.0"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "567f1fd"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
			want: Info{Version: "v0.1.0", Commit: "567f1fd", Modified: true, GoVersion: "go1.27.2"},
		},
		{
			name: "main module without version",
			bi: &debug.BuildInfo{
				GoVersion: "go1.27.2",
				Main:      debug.Module{Path: ModulePath},
			},
			want: Info{Version: "(devel)", GoVersion: "go1.27.2"},
		},
		{
			name: "embedded as a dependency",
			bi: &debug.BuildInfo{
				GoVersion: "go1.27.2",
				Main:      debug.Module{Path: "example.com/host", Version: "v9.9.9"},
				Deps: []*debug.Module{
					{Path: "example.com/other", Version: "v1.0.0"},
					{Path: ModulePath, Version: "v0.2.0"},
				},
			},
			want: Info{Version: "v0.2.0", GoVersion: "go1.27.2"},
		},
		{
			name: "embedded with a replace directive",
			bi: &debug.BuildInfo{
				GoVersion: "go1.27.2",
				Main:      debug.Module{Path: "example.com/host"},
				Deps: []*debug.Module{
					{
						Path:    ModulePath,
						Version: "v0.2.0",
						Replace: &debug.Module{Path: "example.com/fork", Version: "v0.2.1"},
					},
				},
			},
			want: Info{Version: "v0.2.1", GoVersion: "go1.27.2"},
		},
		{
			name: "host program without Clavis",
			bi: &debug.BuildInfo{
				GoVersion: "go1.27.2",
				Main:      debug.Module{Path: "example.com/host"},
			},
			want: Info{Version: "(devel)", GoVersion: "go1.27.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fromBuildInfo(tt.bi)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("fromBuildInfo() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetReportsGoVersion(t *testing.T) {
	t.Parallel()

	if got := Get(); got.GoVersion == "" {
		t.Errorf("Get().GoVersion is empty, want the toolchain version")
	}
}
