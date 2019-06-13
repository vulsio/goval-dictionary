package rdb

import (
	"testing"

	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
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
