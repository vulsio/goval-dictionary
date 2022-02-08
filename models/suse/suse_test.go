package suse

import (
	"reflect"
	"testing"

	"github.com/k0kubun/pp"

	"github.com/vulsio/goval-dictionary/models"
)

func TestWalkSUSE(t *testing.T) {
	var tests = []struct {
		xmlName  string
		cri      Criteria
		tests    map[string]rpmInfoTest
		expected []distroPackage
	}{
		// no OS Package for WalkSUSEFirst
		{
			xmlName: "opensuse.10.2",
			cri: Criteria{
				Criterions: []Criterion{
					{Comment: "apache2-mod_jk less than 4.1.30-13.4"},
				},
			},
			expected: []distroPackage{},
		},
		// no OS Package for WalkSUSESecond
		{
			xmlName: "opensuse.13.1",
			cri: Criteria{
				Criterions: []Criterion{
					{Comment: "mailx-12.5-20.4.1 is installed"},
					{Comment: "kernel-default is not affected"},
				},
			},
			expected: []distroPackage{},
		},
		// OS and Package in the same hierarchy
		{
			xmlName: "opensuse.10.2",
			cri: Criteria{
				Criterions: []Criterion{
					{Comment: "suse102 is installed"},
					{TestRef: "oval:org.opensuse.security:tst:99999999999"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "memcached",
					FixedVersion: "0:1.4.39-3.3.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10.2",
					pack: models.Package{
						Name:    "memcached",
						Version: "0:1.4.39-3.3.2",
					},
				},
			},
		},
		// WalkSUSEFirst
		// openSUSE
		{
			xmlName: "opensuse.10.2",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "suse102 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10.2",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 10
		{
			xmlName: "suse.linux.enterprise.desktop.10",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "sled10 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 10 SP1
		{
			xmlName: "suse.linux.enterprise.desktop.10",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "sled10-sp1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10.1",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 10 SP1-ONLINE
		{
			xmlName: "suse.linux.enterprise.desktop.10",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "sled10-sp1-online is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10.1",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 9
		{
			xmlName: "suse.linux.enterprise.server.9",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
							{TestRef: "oval:org.opensuse.security:tst:99999999998", Comment: "kernel-default is not affected"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "core9 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "mailx",
					FixedVersion: "0:12.5-20.4.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "9",
					pack: models.Package{
						Name:    "mailx",
						Version: "0:12.5-20.4.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 10
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "sles10 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 10-LTSS
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "sles10-ltss is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 10 SP1
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "sles10-sp1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10.1",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 10 SP1-ONLINE
		{
			xmlName: "suse.linux.enterprise.server.10",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "sles10-sp1-online is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "cron",
					FixedVersion: "0:4.1-70",
				},
			},
			expected: []distroPackage{
				{
					osVer: "10.1",
					pack: models.Package{
						Name:    "cron",
						Version: "0:4.1-70",
					},
				},
			},
		},
		// WalkSUSESecond
		// openSUSE 12
		{
			xmlName: "opensuse.12.1",
			cri: Criteria{
				Criterions: []Criterion{
					{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "mailx-12.5-20.4.1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "mailx",
					FixedVersion: "0:12.5-20.4.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "mailx",
						Version: "0:12.5-20.4.1",
					},
				},
			},
		},
		// openSUSE
		{
			xmlName: "opensuse.13.2",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "mailx-12.5-20.4.1 is installed"},
							{TestRef: "oval:org.opensuse.security:tst:99999999998", Comment: "kernel-default is not affected"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "openSUSE 13.2 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "mailx",
					FixedVersion: "0:12.5-20.4.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "13.2",
					pack: models.Package{
						Name:    "mailx",
						Version: "0:12.5-20.4.1",
					},
				},
			},
		},
		// openSUSE NonFree
		{
			xmlName: "opensuse.13.2",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "mailx-12.5-20.4.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "openSUSE 13.2 NonFree is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "mailx",
					FixedVersion: "0:12.5-20.4.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "13.2",
					pack: models.Package{
						Name:    "mailx",
						Version: "0:12.5-20.4.1",
					},
				},
			},
		},
		// openSUSE Leap
		{
			xmlName: "opensuse.leap.42.2",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "krb5-1.12.5-5.13 is installed"},
							{TestRef: "oval:org.opensuse.security:tst:99999999998", Comment: "krb5 is signed with openSUSE key"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "openSUSE Leap 42.2 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.5-5.13",
				},
				"oval:org.opensuse.security:tst:99999999998": {
					Name:           "krb5",
					FixedVersion:   "",
					SignatureKeyID: SignatureKeyid{Text: "text"},
				},
			},
			expected: []distroPackage{
				{
					osVer: "42.2",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.5-5.13",
					},
				},
			},
		},
		// openSUSE Leap NonFree
		{
			xmlName: "opensuse.leap.42.2",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "libunrar-devel-5.5.5-3.1 is installed"},
							{TestRef: "oval:org.opensuse.security:tst:99999999998", Comment: "libunrar-devel is signed with openSUSE key"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "openSUSE Leap 42.2 NonFree is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "libunrar-devel",
					FixedVersion: "0:5.5.5-3.1",
				},
				"oval:org.opensuse.security:tst:99999999998": {
					Name:           "libunrar-devel",
					FixedVersion:   "",
					SignatureKeyID: SignatureKeyid{Text: "text"},
				},
			},
			expected: []distroPackage{
				{
					osVer: "42.2",
					pack: models.Package{
						Name:    "libunrar-devel",
						Version: "0:5.5.5-3.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 12
		{
			xmlName: "suse.linux.enterprise.desktop.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Desktop 12 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.5-39.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Desktop 12 SP1
		{
			xmlName: "suse.linux.enterprise.desktop.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "krb5-1.12.1-19.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Desktop 12 SP1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.1-19.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.1-19.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "krb5-1.12.1-19.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.1-6.3",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.1-6.3",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12 SP1
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 SP1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.1-19.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.1-19.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12-LTSS
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server 12-LTSS is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 12 SP1-LTSS
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server 12 SP1-LTSS is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server 11 SP1-CLIENT-TOOLS
		{
			xmlName: "suse.linux.enterprise.server.11",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server 11 SP1-CLIENT-TOOLS is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "11.1",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for Raspberry Pi 12
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server for Raspberry Pi 12 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.5-39.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for Raspberry Pi 12 SP2
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server for Raspberry Pi 12 SP2 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.5-39.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.2",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "krb5-1.12.5-39.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "krb5",
					FixedVersion: "0:1.12.5-39.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "krb5",
						Version: "0:1.12.5-39.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12-LTSS
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12-LTSS is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12 SP1
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "libecpg6-9.4.6-7.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12 SP1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "libecpg6",
					FixedVersion: "0:9.4.6-7.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "libecpg6",
						Version: "0:9.4.6-7.1",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Server for SAP Applications 11 SP1-CLIENT-TOOLS
		{
			xmlName: "suse.linux.enterprise.server.11",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server for SAP Applications 11 SP1-CLIENT-TOOLS is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "11.1",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
			},
		},
		// SUSE Linux Enterprise Workstation Extension 12
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "libmysqlclient_r18-32bit-10.0.11-6.4 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Workstation Extension 12 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "libmysqlclient_r18-32bit",
					FixedVersion: "0:10.0.11-6.4",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "libmysqlclient_r18-32bit",
						Version: "0:10.0.11-6.4",
					},
				},
			},
		},
		// SUSE Linux Enterprise Workstation Extension 12 SP1
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "libmysqlclient_r18-10.0.21-1.17 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Workstation Extension 12 SP1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "libmysqlclient_r18",
					FixedVersion: "0:10.0.21-1.17",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "libmysqlclient_r18",
						Version: "0:10.0.21-1.17",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Advanced Systems Management 12
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "puppet-server-3.6.2-3.62 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Module for Advanced Systems Management 12 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "puppet-server",
					FixedVersion: "0:3.6.2-3.62",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "puppet-server",
						Version: "0:3.6.2-3.62",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Containers 12
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "sles12-docker-image-1.1.4-20171002 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Module for Containers 12 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "sles12-docker-image",
					FixedVersion: "0:1.1.4-20171002",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "sles12-docker-image",
						Version: "0:1.1.4-20171002",
					},
				},
			},
		},
		// SUSE Linux Enterprise Module for Python 2 15 SP1
		{
			xmlName: "suse.linux.enterprise.server.15",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "python-curses-2.7.17-7.32.2 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Module for Python 2 15 SP1 is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "python-curses",
					FixedVersion: "0:2.7.17-7.32.2",
				},
			},
			expected: []distroPackage{
				{
					osVer: "15.1",
					pack: models.Package{
						Name:    "python-curses",
						Version: "0:2.7.17-7.32.2",
					},
				},
			},
		},
		// Multi Version and Multi Package
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
							{TestRef: "oval:org.opensuse.security:tst:99999999998", Comment: "openssh-askpass-gnome-6.6p1-54.15.1 is installed"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "SUSE Linux Enterprise Server 12-LTSS is installed"},
					{Comment: "SUSE Linux Enterprise Server 12 SP1-LTSS is installed"},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
				"oval:org.opensuse.security:tst:99999999998": {
					Name:         "openssh-askpass-gnome",
					FixedVersion: "0:6.6p1-54.15.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
				{
					osVer: "12",
					pack: models.Package{
						Name:    "openssh-askpass-gnome",
						Version: "0:6.6p1-54.15.1",
					},
				},
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "openssh-askpass-gnome",
						Version: "0:6.6p1-54.15.1",
					},
				},
			},
		},
		// Multi Version and Multi Package2
		{
			xmlName: "suse.linux.enterprise.server.12",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{Comment: "SUSE Linux Enterprise Server 12 is installed"},
						},
						Criterias: []Criteria{
							{
								Criterions: []Criterion{
									{TestRef: "oval:org.opensuse.security:tst:99999999999", Comment: "openssh-6.6p1-54.15.2 is installed"},
								},
							},
						},
					},
					{
						Criterions: []Criterion{
							{Comment: "SUSE Linux Enterprise Server 12 SP1 is installed"},
						},
						Criterias: []Criteria{
							{
								Criterions: []Criterion{
									{TestRef: "oval:org.opensuse.security:tst:99999999998", Comment: "openssh-6.6p1-54.15.1 is installed"},
								},
							},
						},
					},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:org.opensuse.security:tst:99999999999": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.2",
				},
				"oval:org.opensuse.security:tst:99999999998": {
					Name:         "openssh",
					FixedVersion: "0:6.6p1-54.15.1",
				},
			},
			expected: []distroPackage{
				{
					osVer: "12",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.2",
					},
				},
				{
					osVer: "12.1",
					pack: models.Package{
						Name:    "openssh",
						Version: "0:6.6p1-54.15.1",
					},
				},
			},
		},
	}

	for i, tt := range tests {
		actual := collectSUSEPacks(tt.xmlName, tt.cri, tt.tests)
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}

func TestGetOSNameVersion(t *testing.T) {
	var tests = []struct {
		s        string
		expected string
	}{
		{
			s:        "openSUSE 13.2",
			expected: "13.2",
		},
		{
			s:        "openSUSE 13.2 NonFree",
			expected: "13.2",
		},
		{
			s:        "openSUSE Tumbleweed",
			expected: "tumbleweed",
		},
		{
			s:        "openSUSE Leap 42.2",
			expected: "42.2",
		},
		{
			s:        "openSUSE Leap 42.2 NonFree",
			expected: "42.2",
		},
		{
			s:        "SUSE Linux Enterprise Server 12",
			expected: "12",
		},
		{
			s:        "SUSE Linux Enterprise Server 12-LTSS",
			expected: "12",
		},
		{
			s:        "SUSE Linux Enterprise Server 11-SECURITY",
			expected: "11",
		},
		{
			s:        "SUSE Linux Enterprise Server 11-CLIENT-TOOLS",
			expected: "11",
		},
		{
			s:        "SUSE Linux Enterprise Server 12 SP1",
			expected: "12.1",
		},
		{
			s:        "SUSE Linux Enterprise Server 12 SP1-LTSS",
			expected: "12.1",
		},
		{
			s:        "SUSE Linux Enterprise Server 11 SP1-CLIENT-TOOLS",
			expected: "11.1",
		},
		{
			s:        "SUSE Linux Enterprise Server for SAP Applications 12",
			expected: "12",
		},
		{
			s:        "SUSE Linux Enterprise Server for SAP Applications 12-LTSS",
			expected: "12",
		},
		{
			s:        "SUSE Linux Enterprise Server for SAP Applications 11-SECURITY",
			expected: "11",
		},
		{
			s:        "SUSE Linux Enterprise Server for SAP Applications 11-CLIENT-TOOLS",
			expected: "11",
		},
		{
			s:        "SUSE Linux Enterprise Server for SAP Applications 12 SP1",
			expected: "12.1",
		},
		{
			s:        "SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS",
			expected: "12.1",
		},
		{
			s:        "SUSE Linux Enterprise Server for SAP Applications 11 SP1-CLIENT-TOOLS",
			expected: "11.1",
		},
		{
			s:        "SUSE Linux Enterprise Server for Python 2 15 SP1",
			expected: "15.1",
		},
	}

	for i, tt := range tests {
		actual, err := getOSVersion(tt.s)
		if err != nil {
			t.Errorf("[%d] getOSVersion err: %s", i, err)
		}
		if tt.expected != actual {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s, actual: %s\n", i, e, a)
		}
	}
}
