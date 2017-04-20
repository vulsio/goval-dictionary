package models

import (
	"reflect"
	"sort"
	"testing"

	"github.com/k0kubun/pp"
	"github.com/ymomoi/goval-parser/oval"
)

func TestWalkRedHat(t *testing.T) {
	var tests = []struct {
		cri      oval.Criteria
		expected []Package
	}{
		// 0
		{
			cri: oval.Criteria{
				Criterions: []oval.Criterion{
					{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
				},
			},
			expected: []Package{
				{
					Name:    "kernel-headers",
					Version: "0:2.6.32-71.7.1.el6",
				},
			},
		},
		// 1
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
							{Comment: "kernel-headers is signed with Red Hat redhatrelease2 key"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
					{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
				},
			},
			expected: []Package{
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
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "bzip2 is earlier than 0:1.0.5-7.el6_0"},
							{Comment: "bzip2 is signed with Red Hat redhatrelease2 key"},
						},

						Criterias: []oval.Criteria{
							{
								Criterions: []oval.Criterion{
									{Comment: "samba-domainjoin-gui is earlier than 0:3.5.4-68.el6_0.1"},
									{Comment: "samba-domainjoin-gui is signed with Red Hat redhatrelease2 key"},
								},
							},
						},
					},
					{
						Criterions: []oval.Criterion{
							{Comment: "poppler-qt4 is signed with Red Hat redhatrelease2 key"},
							{Comment: "poppler-qt4 is earlier than 0:0.12.4-3.el6_0.1"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
					{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
				},
			},
			expected: []Package{
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
	}

	for i, tt := range tests {
		actual := collectRedHatPacks(tt.cri)
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
