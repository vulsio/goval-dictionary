package fetcher

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRpmNewPackageFromRpm(t *testing.T) {
	tests := []struct {
		name    string
		rpm     Rpm
		want    Package
		wantErr bool
	}{
		{
			name: "normal",
			rpm:  "name-1:1.0-1.module_12345.aarch64",
			want: Package{
				Name:     "name",
				Epoch:    "1",
				Version:  "1.0",
				Release:  "1.module_12345",
				Arch:     "aarch64",
				Filename: "name-1:1.0-1.module_12345.aarch64",
			},
		},
		{
			name: "with.rpm",
			rpm:  "name-1:1.0-1.module_12345.aarch64.rpm",
			want: Package{
				Name:     "name",
				Epoch:    "1",
				Version:  "1.0",
				Release:  "1.module_12345",
				Arch:     "aarch64",
				Filename: "name-1:1.0-1.module_12345.aarch64",
			},
		},
		{
			name: "name-with-hyphen",
			rpm:  "name-with-hyphen-1:1.0-1.module_12345.aarch64",
			want: Package{
				Name:     "name-with-hyphen",
				Epoch:    "1",
				Version:  "1.0",
				Release:  "1.module_12345",
				Arch:     "aarch64",
				Filename: "name-with-hyphen-1:1.0-1.module_12345.aarch64",
			},
		},
		{
			name:    "invalid rpm",
			rpm:     "invalid rpm",
			wantErr: true,
		},
		{
			name:    "can not find release",
			rpm:     "no_release:1.0.aarch64",
			wantErr: true,
		},
		{
			name:    "can not find version",
			rpm:     "no_version:1.0-1.module_12345.aarch64",
			wantErr: true,
		},
		{
			name: "can not find epoch",
			rpm:  "noepoch-1.0-1.module_12345.aarch64",
			want: Package{
				Name:     "noepoch",
				Epoch:    "0",
				Version:  "1.0",
				Release:  "1.module_12345",
				Arch:     "aarch64",
				Filename: "noepoch-1.0-1.module_12345.aarch64",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.rpm.NewPackageFromRpm()
			if (err == nil) == tt.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("(-got +want):\n%s", diff)
			}
		})
	}
}

func TestFedoraUpdatesPerVersionMerge(t *testing.T) {
	tests := []struct {
		name   string
		source FedoraUpdatesPerVersion
		target FedoraUpdatesPerVersion
		want   FedoraUpdatesPerVersion
	}{
		{
			name: "merge success",
			source: FedoraUpdatesPerVersion{
				"35": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update35-1",
						},
						{
							Title: "update35-2",
						},
					},
				},
				"34": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update34-1",
						},
					},
				},
			},
			target: FedoraUpdatesPerVersion{
				"35": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update35-module-1",
						},
					},
				},
				"34": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update34-module-1",
						},
					},
				},
			},
			want: FedoraUpdatesPerVersion{
				"35": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update35-1",
						},
						{
							Title: "update35-2",
						},
						{
							Title: "update35-module-1",
						},
					},
				},
				"34": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update34-1",
						},
						{
							Title: "update34-module-1",
						},
					},
				},
			},
		},
		{
			name: "no panic when some version is missing",
			source: FedoraUpdatesPerVersion{
				"35": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update35-1",
						},
						{
							Title: "update35-2",
						},
					},
				},
				"34": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update34-1",
						},
					},
				},
			},
			target: FedoraUpdatesPerVersion{
				"35": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update35-module-1",
						},
					},
				},
			},
			want: FedoraUpdatesPerVersion{
				"35": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update35-1",
						},
						{
							Title: "update35-2",
						},
						{
							Title: "update35-module-1",
						},
					},
				},
				"34": &FedoraUpdates{
					UpdateList: []FedoraUpdateInfo{
						{
							Title: "update34-1",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.source
			got.merge(&tt.target)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("(-got +want):\n%s", diff)
			}
		})
	}
}

func TestUniquePackages(t *testing.T) {
	opt := cmpopts.SortSlices((func(x, y Package) bool { return strings.Compare(x.Filename, y.Filename) > 0 }))
	tests := []struct {
		name string
		in   []Package
		want []Package
	}{
		{
			name: "normal",
			in: []Package{
				{Filename: "package1"},
				{Filename: "package2"},
				{Filename: "package2"},
				{Filename: "package3"},
				{Filename: "package3"},
				{Filename: "package3"},
			},
			want: []Package{
				{Filename: "package1"},
				{Filename: "package2"},
				{Filename: "package3"},
			},
		},
		{
			name: "no panic when it is blank",
			in:   []Package{},
			want: []Package{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uniquePackages(tt.in)
			if diff := cmp.Diff(got, tt.want, opt); diff != "" {
				t.Errorf("(-got +want):\n%s", diff)
			}
		})
	}
}
