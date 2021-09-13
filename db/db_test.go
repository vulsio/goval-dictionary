package db

import (
	"reflect"
	"testing"

	"github.com/kotakanbe/goval-dictionary/models"
)

func Test_fileterPacksByArch(t *testing.T) {
	type args struct {
		packs []models.Package
		arch  string
	}
	tests := []struct {
		in       args
		expected []models.Package
	}{
		{
			in: args{
				packs: []models.Package{
					{
						Name: "name-x86_64",
						Arch: "x86_64",
					},
					{
						Name: "name-i386",
						Arch: "i386",
					},
				},
				arch: "x86_64",
			},
			expected: []models.Package{{
				Name: "name-x86_64",
				Arch: "x86_64",
			}},
		},
		{
			in: args{
				packs: []models.Package{
					{
						Name: "name-x86_64",
						Arch: "x86_64",
					},
					{
						Name: "name-i386",
						Arch: "i386",
					},
				},
				arch: "",
			},
			expected: []models.Package{
				{
					Name: "name-x86_64",
					Arch: "x86_64",
				},
				{
					Name: "name-i386",
					Arch: "i386",
				},
			},
		},
	}

	for i, tt := range tests {
		if aout := fileterPacksByArch(tt.in.packs, tt.in.arch); !reflect.DeepEqual(aout, tt.expected) {
			t.Errorf("[%d] fileterPacksByArch expected: %#v\n  actual: %#v\n", i, tt.expected, aout)
		}
	}
}

func Test_filterByRedHatMajor(t *testing.T) {
	type args struct {
		packs    []models.Package
		majorVer string
	}
	tests := []struct {
		in       args
		expected []models.Package
	}{
		{
			in: args{
				packs: []models.Package{
					{
						Name:    "name-el7",
						Version: "0:0.0.1-0.0.1.el7",
					},
					{
						Name:    "name-el8",
						Version: "0:0.0.1-0.0.1.el8",
					},
					{
						Name:    "name-module+el7",
						Version: "0:0.1.1-1.module+el7.1.0+7785+0ea9f177",
					},
					{
						Name:    "name-module+el8",
						Version: "0:0.1.1-1.module+el8.1.0+7785+0ea9f177",
					},
				},
				majorVer: "8",
			},
			expected: []models.Package{
				{
					Name:    "name-el8",
					Version: "0:0.0.1-0.0.1.el8",
				},
				{
					Name:    "name-module+el8",
					Version: "0:0.1.1-1.module+el8.1.0+7785+0ea9f177",
				},
			},
		},
		{
			in: args{
				packs: []models.Package{
					{
						Name:    "name-el7",
						Version: "0:0.0.1-0.0.1.el7",
					},
					{
						Name:    "name-el8",
						Version: "0:0.0.1-0.0.1.el8",
					},
					{
						Name:    "name-module+el7",
						Version: "0:0.1.1-1.module+el7.1.0+7785+0ea9f177",
					},
					{
						Name:    "name-module+el8",
						Version: "0:0.1.1-1.module+el8.1.0+7785+0ea9f177",
					},
				},
				majorVer: "",
			},
			expected: []models.Package{
				{
					Name:    "name-el7",
					Version: "0:0.0.1-0.0.1.el7",
				},
				{
					Name:    "name-el8",
					Version: "0:0.0.1-0.0.1.el8",
				},
				{
					Name:    "name-module+el7",
					Version: "0:0.1.1-1.module+el7.1.0+7785+0ea9f177",
				},
				{
					Name:    "name-module+el8",
					Version: "0:0.1.1-1.module+el8.1.0+7785+0ea9f177",
				},
			},
		},
	}

	for i, tt := range tests {
		if aout := filterByRedHatMajor(tt.in.packs, tt.in.majorVer); !reflect.DeepEqual(aout, tt.expected) {
			t.Errorf("[%d] filterByRedHatMajor expected: %#v\n  actual: %#v\n", i, tt.expected, aout)
		}
	}
}
