package models

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/ymomoi/goval-parser/oval"
)

func TestWalkSUSE(t *testing.T) {
	var tests = []struct {
		xmlName  string
		cri      oval.Criteria
		expected []susePackage
	}{
		// no OS Package for WalkSUSEFirst
		{
			xmlName: "opensuse.10.2",
			cri: oval.Criteria{
				Criterions: []oval.Criterion{
					{Comment: "apache2-mod_jk less than 4.1.30-13.4"},
				},
			},
			expected: []susePackage{},
		},
		// no OS Package for WalkSUSESecond
		{
			xmlName: "opensuse.13.1",
			cri: oval.Criteria{
				Criterions: []oval.Criterion{
					{Comment: "mailx-12.5-20.4.1 is installed"},
					{Comment: "kernel-default is not affected"},
				},
			},
			expected: []susePackage{},
		},
		// OS and Package in the same hierarchy
		{
			xmlName: "suse.openstack.cloud.7",
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
		// WalkSUSEFirst
		// openSUSE
		{
			xmlName: "opensuse.10.2",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "suse102 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.OpenSUSE,
					osVer: "10.2",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 10
		{
			xmlName: "suse.linux.enterprise.desktop.10",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "sled10 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseDesktop,
					osVer: "10",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 10 SP1
		{
			xmlName: "suse.linux.enterprise.desktop.10",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "sled10-sp1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseDesktop,
					osVer: "10.sp1",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 10 SP1-ONLINE
		{
			xmlName: "suse.linux.enterprise.desktop.10",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "sled10-sp1-online is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseDesktop, "online"),
					osVer: "10.sp1",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 9
		{
			xmlName: "suse.linux.enterprise.server.9",
			cri: oval.Criteria{
				Criterions: []oval.Criterion{
					{Comment: "mailx-12.5-20.4.1 is installed"},
					{Comment: "kernel-default is not affected"},
				},
			},
			expected: []susePackage{},
		},
		// SUSE Linux Enterprise Server 10
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "sles10 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServer,
					osVer: "10",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 10-LTSS
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "sles10-ltss is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
					osVer: "10",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 10 SP1
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "sles10-sp1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.SUSEEnterpriseServer,
					osVer: "10.sp1",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 10 SP1-ONLINE
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "cron less than 4.1-70"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "sles10-sp1-online is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "online"),
					osVer: "10.sp1",
					pack: Package{
						Name:    "cron",
						Version: "4.1-70",
					},
				},
			},
		},
		// WalkSUSESecond
		// openSUSE 12
		{
			xmlName: "opensuse.12.1",
			cri: oval.Criteria{
				Criterions: []oval.Criterion{
					{Comment: "mailx-12.5-20.4.1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    config.OpenSUSE,
					osVer: "12.1",
					pack: Package{
						Name:    "mailx",
						Version: "12.5-20.4.1",
					},
				},
			},
		},
		// openSUSE
		{
			xmlName: "opensuse.13.2",
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
			xmlName: "opensuse.13.2",
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
					os:    fmt.Sprintf("%s.%s", config.OpenSUSE, "nonfree"),
					osVer: "13.2",
					pack: Package{
						Name:    "mailx",
						Version: "12.5-20.4.1",
					},
				},
			},
		},
		// openSUSE Leap
		{
			xmlName: "opensuse.leap.42.2",
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
			xmlName: "opensuse.leap.42.2",
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
					os:    fmt.Sprintf("%s.%s", config.OpenSUSELeap, "nonfree"),
					osVer: "42.2",
					pack: Package{
						Name:    "libunrar-devel",
						Version: "5.5.5-3.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 12
		{
			xmlName: "suse.linux.enterprise.desktop.12",
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
			xmlName: "suse.linux.enterprise.desktop.12",
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
			xmlName: "suse.linux.enterprise.server.12",
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
			xmlName: "suse.linux.enterprise.server.12",
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
					osVer: "12.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 11 SP1-CLIENT-TOOLS
		{
			xmlName: "suse.linux.enterprise.server.11",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server 11 SP1-CLIENT-TOOLS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "client.tools"),
					osVer: "11.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for Raspberry Pi 12
		{
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.raspberry.pi"),
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.raspberry.pi"),
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications"),
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.ltss"),
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications"),
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.ltss"),
					osVer: "12.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 11 SP1-CLIENT-TOOLS
		{
			xmlName: "suse.linux.enterprise.server.11",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 11 SP1-CLIENT-TOOLS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.client.tools"),
					osVer: "11.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Workstation Extension 12
		{
			xmlName: "suse.linux.enterprise.server.12",
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
			xmlName: "suse.linux.enterprise.server.12",
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseModule, "for.advanced.systems.management"),
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
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseModule, "for.containers"),
					osVer: "12",
					pack: Package{
						Name:    "sles12-docker-image",
						Version: "1.1.4-20171002",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Python 2 15 SP1
		{
			xmlName: "suse.linux.enterprise.server.15",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "python-curses-2.7.17-7.32.2 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE Linux Enterprise Module for Python 2 15 SP1 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseModule, "for.python.2"),
					osVer: "15.sp1",
					pack: Package{
						Name:    "python-curses",
						Version: "2.7.17-7.32.2",
					},
				},
			},
		},
		// SUSE OpenStack Cloud 7
		{
			xmlName: "suse.openstack.cloud.7",
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
		// SUSE OpenStack Cloud Crowbar 9
		{
			xmlName: "suse.openstack.cloud.9",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "glibc-2.22-62.22.5 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE OpenStack Cloud Crowbar 9 is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEOpenstackCloud, "crowbar"),
					osVer: "9",
					pack: Package{
						Name:    "glibc",
						Version: "2.22-62.22.5",
					},
				},
			},
		},
		// SUSE OpenStack Cloud 6-LTSS
		{
			xmlName: "suse.openstack.cloud.6",
			cri: oval.Criteria{
				Criterias: []oval.Criteria{
					{
						Criterions: []oval.Criterion{
							{Comment: "glibc-2.22-62.22.5 is installed"},
						},
					},
				},
				Criterions: []oval.Criterion{
					{Comment: "SUSE OpenStack Cloud 6-LTSS is installed"},
				},
			},
			expected: []susePackage{
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEOpenstackCloud, "ltss"),
					osVer: "6",
					pack: Package{
						Name:    "glibc",
						Version: "2.22-62.22.5",
					},
				},
			},
		},
		// Multi OS and Multi Package
		{
			xmlName: "suse.linux.enterprise.server.12",
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
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
					osVer: "12",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
					osVer: "12.sp1",
					pack: Package{
						Name:    "openssh",
						Version: "6.6p1-54.15.2",
					},
				},
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
					osVer: "12",
					pack: Package{
						Name:    "openssh-askpass-gnome",
						Version: "6.6p1-54.15.1",
					},
				},
				{
					os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
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
		actual := collectSUSEPacks(tt.xmlName, tt.cri)
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}

func TestGetOSNameVersion(t *testing.T) {
	type expected struct {
		os    string
		osVer string
	}
	var tests = []struct {
		s        string
		expected expected
	}{
		{
			s: "openSUSE 13.2",
			expected: expected{
				os:    config.OpenSUSE,
				osVer: "13.2",
			},
		},
		{
			s: "openSUSE 13.2 NonFree",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.OpenSUSE, "nonfree"),
				osVer: "13.2",
			},
		},
		{
			s: "openSUSE Leap 42.2",
			expected: expected{
				os:    config.OpenSUSELeap,
				osVer: "42.2",
			},
		},
		{
			s: "openSUSE Leap 42.2 NonFree",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.OpenSUSELeap, "nonfree"),
				osVer: "42.2",
			},
		},
		{
			s: "SUSE Linux Enterprise Server 12",
			expected: expected{
				os:    config.SUSEEnterpriseServer,
				osVer: "12",
			},
		},
		{
			s: "SUSE Linux Enterprise Server 12-LTSS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
				osVer: "12",
			},
		},
		{
			s: "SUSE Linux Enterprise Server 11-SECURITY",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "security"),
				osVer: "11",
			},
		},
		{
			s: "SUSE Linux Enterprise Server 11-CLIENT-TOOLS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "client.tools"),
				osVer: "11",
			},
		},
		{
			s: "SUSE Linux Enterprise Server 12 SP1",
			expected: expected{
				os:    config.SUSEEnterpriseServer,
				osVer: "12.sp1",
			},
		},
		{
			s: "SUSE Linux Enterprise Server 12 SP1-LTSS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "ltss"),
				osVer: "12.sp1",
			},
		},
		{
			s: "SUSE Linux Enterprise Server 11 SP1-CLIENT-TOOLS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "client.tools"),
				osVer: "11.sp1",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for SAP Applications 12",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications"),
				osVer: "12",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for SAP Applications 12-LTSS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.ltss"),
				osVer: "12",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for SAP Applications 11-SECURITY",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.security"),
				osVer: "11",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for SAP Applications 11-CLIENT-TOOLS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.client.tools"),
				osVer: "11",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for SAP Applications 12 SP1",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications"),
				osVer: "12.sp1",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.ltss"),
				osVer: "12.sp1",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for SAP Applications 11 SP1-CLIENT-TOOLS",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.sap.applications.client.tools"),
				osVer: "11.sp1",
			},
		},
		{
			s: "SUSE Linux Enterprise Server for Python 2 15 SP1",
			expected: expected{
				os:    fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, "for.python.2"),
				osVer: "15.sp1",
			},
		},
	}

	for i, tt := range tests {
		osName, osVer, err := getOSNameVersion(tt.s)
		if err != nil {
			t.Errorf("[%d] getAccurateOSNameVersion err: %w", i, err)
		}

		actual := expected{
			os:    osName,
			osVer: osVer,
		}

		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}
