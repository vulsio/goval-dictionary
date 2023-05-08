package redhat

import (
	"reflect"
	"sort"
	"testing"

	"github.com/k0kubun/pp"

	"github.com/vulsio/goval-dictionary/models"
)

func TestWalkRedHat(t *testing.T) {
	var tests = []struct {
		cri      Criteria
		expected []models.Package
	}{
		// 0
		{
			cri: Criteria{
				Criterions: []Criterion{
					{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
				},
			},
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
						Criterions: []Criterion{
							{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
							{Comment: "kernel-headers is signed with Red Hat redhatrelease2 key"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
					{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
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
						Criterions: []Criterion{
							{Comment: "bzip2 is earlier than 0:1.0.5-7.el6_0"},
							{Comment: "bzip2 is signed with Red Hat redhatrelease2 key"},
						},

						Criterias: []Criteria{
							{
								Criterions: []Criterion{
									{Comment: "samba-domainjoin-gui is earlier than 0:3.5.4-68.el6_0.1"},
									{Comment: "samba-domainjoin-gui is signed with Red Hat redhatrelease2 key"},
								},
							},
						},
					},
					{
						Criterions: []Criterion{
							{Comment: "poppler-qt4 is signed with Red Hat redhatrelease2 key"},
							{Comment: "poppler-qt4 is earlier than 0:0.12.4-3.el6_0.1"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
					{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
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
							{Comment: "ruby is earlier than 0:2.5.5-105.module+el8.1.0+3656+f80bfa1d"},
							{Comment: "ruby is signed with Red Hat redhatrelease2 key"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "Red Hat Enterprise Linux 8 is installed"},
					{Comment: "Module ruby:2.5 is enabled"},
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
		// 4
		{
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterias: []Criteria{
							{
								Criterions: []Criterion{
									{Comment: "rpm is earlier than 0:4.8.0-12.el6_0.2"},
								},
							},
						},
						Criterions: []Criterion{
							{Comment: "Red Hat Enterprise Linux 6 is installed"},
						},
					},
					{
						Criterias: []Criteria{
							{
								Criterions: []Criterion{
									{Comment: "rpm is earlier than 0:4.8.0-19.el6_2.1"},
								},
							},
						},
						Criterions: []Criterion{
							{Comment: "Red Hat Enterprise Linux 6 is installed"},
						},
					},
				},
			},
			expected: []models.Package{
				{
					Name:    "rpm",
					Version: "0:4.8.0-19.el6_2.1",
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
