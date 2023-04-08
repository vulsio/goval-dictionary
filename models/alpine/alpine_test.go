package alpine

import (
	"gopkg.in/yaml.v2"
	"reflect"
	"testing"

	"github.com/k0kubun/pp"

	"github.com/vulsio/goval-dictionary/models"
)

func TestExtractPackageType1(t *testing.T) {
	var tests = []struct {
		oval     string
		expected []models.Package
	}{
		{
			oval: `
apkurl: '{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk'
archs:
- aarch64
- armhf
- armv7
- mips64
- ppc64le
- s390x
- x86
- x86_64
reponame: main
urlprefix: https://dl-cdn.alpinelinux.org/alpine
distroversion: v3.13
packages:
- pkg:
    name: sqlite
    secfixes:
      3.28.0-r0:
      - CVE-2019-5018
      - CVE-2019-8457
            `,
			expected: []models.Package{
				{
					Name:    "sqlite",
					Version: "3.28.0-r0",
				},
			},
		},
	}

	for i, tt := range tests {
		var secDb SecDB[PackageType1]
		if err := yaml.Unmarshal([]byte(tt.oval), &secDb); err != nil {
			t.Errorf("[%d] marshall error %s", i, err.Error())
		}

		defs := ConvertToModel(&secDb)
		actual := defs[0].AffectedPacks
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}

func TestExtractPackageType2(t *testing.T) {
	var tests = []struct {
		oval     string
		expected []models.Package
	}{
		{
			oval: `
apkurl: '{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk'
archs:
- aarch64
- armhf
- armv7
- ppc64le
- s390x
- x86
- x86_64
reponame: main
urlprefix: https://dl-cdn.alpinelinux.org/alpine
distroversion: v3.14
packages:
- pkg:
    name: sqlite
    secfixes:
    - version: 3.34.1-r0
      fixes:
      - identifiers:
        - CVE-2021-20227
        linenr: 37
      linenr: 36
            `,
			expected: []models.Package{
				{
					Name:    "sqlite",
					Version: "3.34.1-r0",
				},
			},
		},
	}

	for i, tt := range tests {
		var secDb SecDB[PackageType2]
		if err := yaml.Unmarshal([]byte(tt.oval), &secDb); err != nil {
			t.Errorf("[%d] marshall error %s", i, err.Error())
		}

		defs := ConvertToModel(&secDb)
		actual := defs[0].AffectedPacks
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}
