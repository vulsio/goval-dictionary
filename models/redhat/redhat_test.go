package redhat

import (
	"reflect"
	"sort"
	"testing"

	"github.com/k0kubun/pp"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/models"
)

func TestParseTests(t *testing.T) {
	var tests = []struct {
		root     Root
		expected map[string]rpmInfoTest
		wantErr  error
	}{
		{
			root: Root{
				Objects: Objects{
					RpminfoObjects: []RpminfoObject{
						{
							ID:   "oval:com.redhat.rhsa:obj:99999999999",
							Name: "cloud-init",
						},
						{
							ID:   "oval:com.redhat.rhsa:obj:99999999998",
							Name: "firefox",
						},
					},
				},
				States: States{
					RpminfoStates: []RpminfoState{
						{
							ID: "oval:com.redhat.rhsa:ste:99999999999",
							Evr: struct {
								Text      string "xml:\",chardata\""
								Datatype  string "xml:\"datatype,attr\""
								Operation string "xml:\"operation,attr\""
							}{
								Datatype:  "evr_string",
								Operation: "less than",
								Text:      "1:1.8.0.322.b06-2.el8_5",
							},
							Arch: struct {
								Text      string "xml:\",chardata\""
								Datatype  string "xml:\"datatype,attr\""
								Operation string "xml:\"operation,attr\""
							}{
								Datatype:  "string",
								Operation: "pattern match",
								Text:      "aarch64|ppc64le|x86_64",
							},
						},
						{
							ID: "oval:com.redhat.rhsa:ste:99999999998",
							Evr: struct {
								Text      string "xml:\",chardata\""
								Datatype  string "xml:\"datatype,attr\""
								Operation string "xml:\"operation,attr\""
							}{
								Datatype:  "evr_string",
								Operation: "less than",
								Text:      "0:60.6.1-1.el8",
							},
							Arch: struct {
								Text      string "xml:\",chardata\""
								Datatype  string "xml:\"datatype,attr\""
								Operation string "xml:\"operation,attr\""
							}{
								Datatype:  "string",
								Operation: "equals",
								Text:      "x86_64",
							},
						},
					},
				},
				Tests: Tests{
					RpminfoTests: []RpminfoTest{
						{
							ID:     "oval:com.redhat.rhsa:tst:99999999999",
							Check:  "at least one",
							Object: ObjectRef{ObjectRef: "oval:com.redhat.rhsa:obj:99999999999"},
							State:  StateRef{StateRef: "oval:com.redhat.rhsa:ste:99999999999"},
						},
						{
							ID:     "oval:com.redhat.rhsa:tst:99999999998",
							Check:  "at least one",
							Object: ObjectRef{ObjectRef: "oval:com.redhat.rhsa:obj:99999999998"},
							State:  StateRef{StateRef: "oval:com.redhat.rhsa:ste:99999999998"},
						},
					},
				},
			},
			expected: map[string]rpmInfoTest{
				"oval:com.redhat.rhsa:tst:99999999999": {
					Name:         "cloud-init",
					FixedVersion: "1:1.8.0.322.b06-2.el8_5",
					Arch:         []string{"aarch64", "ppc64le", "x86_64"},
				},
				"oval:com.redhat.rhsa:tst:99999999998": {
					Name:         "firefox",
					FixedVersion: "0:60.6.1-1.el8",
					Arch:         []string{"x86_64"},
				},
			},
		},
		{
			root: Root{
				Objects: Objects{
					RpminfoObjects: []RpminfoObject{},
				},
				States: States{
					RpminfoStates: []RpminfoState{
						{
							ID: "oval:com.redhat.rhsa:ste:99999999999",
							Evr: struct {
								Text      string "xml:\",chardata\""
								Datatype  string "xml:\"datatype,attr\""
								Operation string "xml:\"operation,attr\""
							}{
								Datatype:  "evr_string",
								Operation: "less than",
								Text:      "1:1.8.0.322.b06-2.el8_5",
							},
							Arch: struct {
								Text      string "xml:\",chardata\""
								Datatype  string "xml:\"datatype,attr\""
								Operation string "xml:\"operation,attr\""
							}{
								Datatype:  "string",
								Operation: "pattern match",
								Text:      "aarch64|ppc64le|x86_64",
							},
						},
					},
				},
				Tests: Tests{
					RpminfoTests: []RpminfoTest{
						{
							ID:     "oval:com.redhat.rhsa:tst:99999999999",
							Check:  "at least one",
							Object: ObjectRef{ObjectRef: "oval:com.redhat.rhsa:obj:99999999999"},
							State:  StateRef{StateRef: "oval:com.redhat.rhsa:ste:99999999999"},
						},
					},
				},
			},
			wantErr: xerrors.Errorf("Failed to follow test refs. err: %w", xerrors.Errorf("Failed to find object ref. object ref: %s, test ref: %s, err: invalid tests data", "oval:com.redhat.rhsa:obj:99999999999", "oval:com.redhat.rhsa:tst:99999999999")),
		},
		{
			root: Root{
				Objects: Objects{
					RpminfoObjects: []RpminfoObject{
						{
							ID:   "oval:com.redhat.rhsa:obj:99999999999",
							Name: "cloud-init",
						},
					},
				},
				States: States{
					RpminfoStates: []RpminfoState{},
				},
				Tests: Tests{
					RpminfoTests: []RpminfoTest{
						{
							ID:     "oval:com.redhat.rhsa:tst:99999999999",
							Check:  "at least one",
							Object: ObjectRef{ObjectRef: "oval:com.redhat.rhsa:obj:99999999999"},
							State:  StateRef{StateRef: "oval:com.redhat.rhsa:ste:99999999999"},
						},
					},
				},
			},
			wantErr: xerrors.Errorf("Failed to follow test refs. err: %w", xerrors.Errorf("Failed to find state ref. state ref: %s, test ref: %s, err: invalid tests data", "oval:com.redhat.rhsa:ste:99999999999", "oval:com.redhat.rhsa:tst:99999999999")),
		},
	}

	for i, tt := range tests {
		actual, err := parseTests(tt.root)
		if tt.wantErr != nil {
			if err.Error() != tt.wantErr.Error() {
				t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, tt.wantErr, err)
				continue
			}
		}

		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}

func TestWalkCriterion(t *testing.T) {
	var tests = []struct {
		cri      Criteria
		tests    map[string]rpmInfoTest
		expected []models.Package
	}{
		// 0
		{
			cri: Criteria{
				Criterions: []Criterion{
					{TestRef: "oval:com.redhat.rhsa:tst:99999999999"}},
			},
			tests: map[string]rpmInfoTest{"oval:com.redhat.rhsa:tst:99999999999": {
				Name:         "kernel-headers",
				FixedVersion: "0:2.6.32-71.7.1.el6",
			}},
			expected: []models.Package{
				{
					Name:    "kernel-headers",
					Version: "0:2.6.32-71.7.1.el6",
				},
			},
		},
		// 1
		{
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{{TestRef: "oval:com.redhat.rhsa:tst:99999999999"}},
					},
				},
				Criterions: []Criterion{{TestRef: "oval:com.redhat.rhsa:tst:99999999998"}},
			},
			tests: map[string]rpmInfoTest{
				"oval:com.redhat.rhsa:tst:99999999999": {
					Name:         "kernel-headers",
					FixedVersion: "0:2.6.32-71.7.1.el6",
				},
				"oval:com.redhat.rhsa:tst:99999999998": {
					Name:         "kernel-kdump",
					FixedVersion: "0:2.6.32-71.7.1.el6",
				},
			},
			expected: []models.Package{
				{
					Name:    "kernel-headers",
					Version: "0:2.6.32-71.7.1.el6",
				},
				{
					Name:    "kernel-kdump",
					Version: "0:2.6.32-71.7.1.el6",
				},
			},
		},
		// 2
		{
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{{TestRef: "oval:com.redhat.rhsa:tst:99999999999"}},

						Criterias: []Criteria{
							{
								Criterions: []Criterion{{TestRef: "oval:com.redhat.rhsa:tst:99999999998"}},
							},
						},
					},
					{
						Criterions: []Criterion{{TestRef: "oval:com.redhat.rhsa:tst:99999999997"}},
					},
				},
				Criterions: []Criterion{{TestRef: "oval:com.redhat.rhsa:tst:99999999996"}},
			},
			tests: map[string]rpmInfoTest{
				"oval:com.redhat.rhsa:tst:99999999999": {
					Name:         "bzip2",
					FixedVersion: "0:1.0.5-7.el6_0",
				},
				"oval:com.redhat.rhsa:tst:99999999998": {
					Name:         "samba-domainjoin-gui",
					FixedVersion: "0:3.5.4-68.el6_0.1",
				},
				"oval:com.redhat.rhsa:tst:99999999997": {
					Name:         "poppler-qt4",
					FixedVersion: "0:0.12.4-3.el6_0.1",
				},
				"oval:com.redhat.rhsa:tst:99999999996": {
					Name:         "kernel-kdump",
					FixedVersion: "0:2.6.32-71.7.1.el6",
				},
			},
			expected: []models.Package{
				{
					Name:    "bzip2",
					Version: "0:1.0.5-7.el6_0",
				},
				{
					Name:    "samba-domainjoin-gui",
					Version: "0:3.5.4-68.el6_0.1",
				},
				{
					Name:    "poppler-qt4",
					Version: "0:0.12.4-3.el6_0.1",
				},
				{
					Name:    "kernel-kdump",
					Version: "0:2.6.32-71.7.1.el6",
				},
			},
		},
		// 3 dnf module
		{
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:com.redhat.rhsa:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "Red Hat Enterprise Linux 8 is installed"},
					{Comment: "Module ruby:2.5 is enabled"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:com.redhat.rhsa:tst:99999999999": {
					Name:         "ruby",
					FixedVersion: "0:2.5.5-105.module+el8.1.0+3656+f80bfa1d",
				},
			},
			expected: []models.Package{
				{
					Name:            "ruby",
					Version:         "0:2.5.5-105.module+el8.1.0+3656+f80bfa1d",
					ModularityLabel: "ruby:2.5",
				},
			},
		},
	}

	for i, tt := range tests {
		actual := collectRedHatPacks(tt.cri, tt.tests)
		sort.Slice(actual, func(i, j int) bool {
			return actual[i].Name < actual[j].Name
		})
		sort.Slice(tt.expected, func(i, j int) bool {
			return tt.expected[i].Name < tt.expected[j].Name
		})

		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}
