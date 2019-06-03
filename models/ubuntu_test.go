package models

import (
	"reflect"
	"testing"

	"github.com/k0kubun/pp"
)

func TestParseNotFixedYet(t *testing.T) {
	var tests = []struct {
		comment  string
		expected Package
	}{
		// Ubuntu 14
		{
			comment: `The 'php-openid' package in trusty is affected and needs fixing.`,
			expected: Package{
				Name:        "php-openid",
				NotFixedYet: true,
			},
		},
		// Ubuntu 16, 18
		{
			comment: `xine-console package in bionic is affected and needs fixing.`,
			expected: Package{
				Name:        "xine-console",
				NotFixedYet: true,
			},
		},
	}

	for i, tt := range tests {
		actual, ok := parseNotFixedYet(tt.comment)
		if !ok {
			t.Errorf("[%d]: no match: %s\n", i, tt.comment)
			return
		}
		if !reflect.DeepEqual(tt.expected, *actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", *actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}

func TestParseNotDecided(t *testing.T) {
	var tests = []struct {
		comment  string
		expected Package
	}{
		// Ubuntu 14
		{
			comment: `The 'ruby1.9.1' package in trusty is affected, but a decision has been made to defer addressing it (note: '2019-04-10').`,
			expected: Package{
				Name:        "ruby1.9.1",
				NotFixedYet: true,
			},
		},
		// Ubuntu 16, 18
		{
			comment: `libxerces-c-samples package in bionic is affected, but a decision has been made to defer addressing it (note: '2019-01-01').`,
			expected: Package{
				Name:        "libxerces-c-samples",
				NotFixedYet: true,
			},
		},
	}

	for i, tt := range tests {
		actual, ok := parseNotDecided(tt.comment)
		if !ok {
			t.Errorf("[%d]: no match: %s\n", i, tt.comment)
			return
		}
		if !reflect.DeepEqual(tt.expected, *actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", *actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}

func TestParseFixed(t *testing.T) {
	var tests = []struct {
		comment  string
		expected Package
	}{
		{
			comment: `The 'poppler' package in trusty was vulnerable but has been fixed (note: '0.10.5-1ubuntu2').`,
			expected: Package{
				Name:    "poppler",
				Version: "0.10.5-1ubuntu2",
			},
		},
		{
			comment: `iproute2 package in bionic, is related to the CVE in some way and has been fixed (note: '3.12.0-2').`,
			expected: Package{
				Name:    "iproute2",
				Version: "3.12.0-2",
			},
		},
		{
			comment: `iproute2 package in bionic, is related to the CVE in some way and has been fixed (note: '3.12.0-2 ').`,
			expected: Package{
				Name:    "iproute2",
				Version: "3.12.0-2",
			},
		},
	}

	for i, tt := range tests {
		actual, ok := parseFixed(tt.comment)
		if !ok {
			t.Errorf("[%d]: no match: %s\n", i, tt.comment)
			return
		}
		if !reflect.DeepEqual(tt.expected, *actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", *actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}
