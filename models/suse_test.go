package models

import (
	"reflect"
	"testing"

	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/ymomoi/goval-parser/oval"
)

func TestWalkSUSE(t *testing.T) {
	var tests = []struct {
		cri      oval.Criteria
		expected []susePackage
	}{
		// no OS Package
		{
			cri: oval.Criteria{
				Criterions: []oval.Criterion{
					{Comment: "mailx-12.5-20.4.1 is installed"},
					{Comment: "kernel-default is not affected"},
				},
			},
			expected: []susePackage{},
		},
		//
		{
			cri: oval.Criteria{
				Criterions: []oval.Criterion{
					{Comment: "SUSE OpenStack Cloud 7 is installed"},
					{Comment: "memcached-1.4.39-3.3.2 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEOpenstackCloud,
					osVer: "7",
					pack: Package{
						Name:    "memcached",
						Version: "1.4.39-3.3.2",
					},
				},
			},
		},
		// openSUSE
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "mailx-12.5-20.4.1 is installed"},
							{Comment: "kernel-default is not affected"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "openSUSE 13.2 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.OpenSUSE,
					osVer: "13.2",
					pack: Package{
						Name:    "mailx",
						Version: "12.5-20.4.1",
					},
				},
			},
		},
		// openSUSE NonFree
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "mailx-12.5-20.4.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "openSUSE 13.2 NonFree is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.OpenSUSE,
					osVer: "13.2.nonfree",
					pack: Package{
						Name:    "mailx",
						Version: "12.5-20.4.1",
					},
				},
			},
		},
		// openSUSE Leap
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.5-5.13 is installed"},
							{Comment: "krb5 is signed with openSUSE key"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "openSUSE Leap 42.2 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.OpenSUSELeap,
					osVer: "42.2",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.5-5.13",
					},
				},
			},
		},
		// openSUSE Leap NonFree
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "libunrar-devel-5.5.5-3.1 is installed"},
							{Comment: "libunrar-devel is signed with openSUSE key"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "openSUSE Leap 42.2 NonFree is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.OpenSUSELeap,
					osVer: "42.2.nonfree",
					pack: Package{
						Name:    "libunrar-devel",
						Version: "5.5.5-3.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Desktop 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseDesktop,
					osVer: "12",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 12 SP1
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.1-19.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Desktop 12 SP1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseDesktop,
					osVer: "12.sp1",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.1-19.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.1-6.3 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServer,
					osVer: "12",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.1-6.3",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12 SP1
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.1-19.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 SP1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServer,
					osVer: "12.sp1",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.1-19.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12-LTSS
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12-LTSS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerLTSS,
					osVer: "12",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12 SP1-LTSS
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 SP1-LTSS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerLTSS,
					osVer: "12.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12 SP2-BCL
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "glibc-2.22-62.22.5 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 SP2-BCL is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerBCL,
					osVer: "12.sp2",
					pack: Package{
						Name:    "glibc",
						Version: "2.22-62.22.5",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12 SP2-ESPOS
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "glibc-2.22-62.22.5 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 SP2-ESPOS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerESPOS,
					osVer: "12.sp2",
					pack: Package{
						Name:    "glibc",
						Version: "2.22-62.22.5",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12 SP3-TERADATA
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "glibc-2.22-62.22.5 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 SP3-TERADATA is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerTERADATA,
					osVer: "12.sp3",
					pack: Package{
						Name:    "glibc",
						Version: "2.22-62.22.5",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for Raspberry Pi 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server for Raspberry Pi 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerRaspberryPi,
					osVer: "12",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for Raspberry Pi 12 SP2
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server for Raspberry Pi 12 SP2 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerRaspberryPi,
					osVer: "12.sp2",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerSAP,
					osVer: "12",
					pack: Package{
						Name:    "krb5",
						Version: "1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12-LTSS
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12-LTSS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerSAPLTSS,
					osVer: "12",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12 SP1
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "libecpg6-9.4.6-7.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12 SP1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerSAP,
					osVer: "12.sp1",
					pack: Package{
						Name:    "libecpg6",
						Version: "9.4.6-7.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerSAPLTSS,
					osVer: "12.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Workstation Extension 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "libmysqlclient_r18-32bit-10.0.11-6.4 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Workstation Extension 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseWorkstation,
					osVer: "12",
					pack: Package{
						Name:    "libmysqlclient_r18-32bit",
						Version: "10.0.11-6.4",
					},
				},
			},
		},
		// SUSE Linux Enterprise Workstation Extension 12 SP1
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "libmysqlclient_r18-10.0.21-1.17 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Workstation Extension 12 SP1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseWorkstation,
					osVer: "12.sp1",
					pack: Package{
						Name:    "libmysqlclient_r18",
						Version: "10.0.21-1.17",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Advanced Systems Management 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "puppet-server-3.6.2-3.62 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for Advanced Systems Management 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseModuleAdvancedSystemsManagement,
					osVer: "12",
					pack: Package{
						Name:    "puppet-server",
						Version: "3.6.2-3.62",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Containers 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "sles12-docker-image-1.1.4-20171002 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for Containers 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseModuleContainers,
					osVer: "12",
					pack: Package{
						Name:    "sles12-docker-image",
						Version: "1.1.4-20171002",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for High Performance Computing 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "libnss_slurm2_20_02-20.02.3-3.5.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for High Performance Computing 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseModuleHPC,
					osVer: "12",
					pack: Package{
						Name:    "libnss_slurm2_20_02",
						Version: "20.02.3-3.5.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Legacy 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "libopenssl0_9_8-0.9.8j-97.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for Legacy 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseModuleLegacy,
					osVer: "12",
					pack: Package{
						Name:    "libopenssl0_9_8",
						Version: "0.9.8j-97.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Public Cloud 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "kernel-ec2-3.12.74-60.64.40.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for Public Cloud 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseModulePublicCloud,
					osVer: "12",
					pack: Package{
						Name:    "kernel-ec2",
						Version: "3.12.74-60.64.40.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Toolchain 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "gcc5-ada-5.3.1+r233831-9.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for Toolchain 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseModuleToolchain,
					osVer: "12",
					pack: Package{
						Name:    "gcc5-ada",
						Version: "5.3.1+r233831-9.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Web Scripting 12
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "apache2-mod_php5-5.5.14-33.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for Web Scripting 12 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseModuleWebScripting,
					osVer: "12",
					pack: Package{
						Name:    "apache2-mod_php5",
						Version: "5.5.14-33.2",
					},
				},
			},
		},
		// SUSE OpenStack Cloud 7
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "glibc-2.22-62.22.5 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE OpenStack Cloud 7 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEOpenstackCloud,
					osVer: "7",
					pack: Package{
						Name:    "glibc",
						Version: "2.22-62.22.5",
					},
				},
			},
		},
		// Multi OS and Multi Package
		{
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "openssh-6.6p1-54.15.2 is installed"},
							{Comment: "openssh-askpass-gnome-6.6p1-54.15.1 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 12-LTSS is installed"},
					{Comment: "SUSE Linux Enterprise Server 12 SP1-LTSS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServerLTSS,
					osVer: "12",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
				{
					os:    config.SUSEEnterpriseServerLTSS,
					osVer: "12.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
				{
					os:    config.SUSEEnterpriseServerLTSS,
					osVer: "12",
					pack: Package{
						Name:    "openssh-askpass-gnome",
						Version: "6.6p1-54.15.1",
					},
				},
				{
					os:    config.SUSEEnterpriseServerLTSS,
					osVer: "12.sp1",
					pack: Package{
						Name:    "openssh-askpass-gnome",
						Version: "6.6p1-54.15.1",
					},
				},
			},
		},
	}

	for i, tt := range tests {
		actual := collectSUSEPacks(tt.cri)
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}
