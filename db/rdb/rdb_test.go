package rdb

import (
	"reflect"
	"testing"

	"github.com/kotakanbe/goval-dictionary/models"
)

func Test_majorMinor(t *testing.T) {
	type args struct {
		osVer string
	}
	tests := []struct {
		name                  string
		args                  args
		wantMajorMinorVersion string
	}{
		{
			"3",
			args{"3"},
			"3",
		},
		{
			"3.9",
			args{"3.9"},
			"3.9",
		},
		{
			"3.9.2",
			args{"3.9.2"},
			"3.9",
		},
		{
			"3.9.2.2",
			args{"3.9.2.2"},
			"3.9",
		},
		{
			"3.9.2.2",
			args{"3.9.2.2"},
			"3.9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMajorMinorVersion := majorDotMinor(tt.args.osVer); gotMajorMinorVersion != tt.wantMajorMinorVersion {
				t.Errorf("majorMinor() = %v, want %v", gotMajorMinorVersion, tt.wantMajorMinorVersion)
			}
		})
	}
}

func Test_splitChunkIntoDefinitions(t *testing.T) {
	type args struct {
		defs      []models.Definition
		rootID    uint
		chunkSize int
	}
	tests := []struct {
		name     string
		input    args
		expected [][]models.Definition
	}{
		{
			name: "",
			input: args{
				defs:      []models.Definition{{Title: "test1"}, {Title: "test2"}, {Title: "test3"}, {Title: "test4"}, {Title: "test5"}},
				rootID:    2,
				chunkSize: 2,
			},
			expected: [][]models.Definition{
				{{RootID: 2, Title: "test1"}, {RootID: 2, Title: "test2"}},
				{{RootID: 2, Title: "test3"}, {RootID: 2, Title: "test4"}},
				{{RootID: 2, Title: "test5"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotChunks := splitChunkIntoDefinitions(tt.input.defs, tt.input.rootID, tt.input.chunkSize); !reflect.DeepEqual(gotChunks, tt.expected) {
				t.Errorf("splitChunkIntoDefinitions() = %v, want %v", gotChunks, tt.expected)
			}
		})
	}
}
