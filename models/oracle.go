package models

import (
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/ymomoi/goval-parser/oval"
)

// ConvertOracleToModel Convert OVAL to models
func ConvertOracleToModel(root *oval.Root) (defs map[string][]Definition) {
	osVerDefs := map[string][]Definition{}

	for _, ovaldef := range root.Definitions.Definitions {
		if strings.Contains(ovaldef.Description, "** REJECT **") {
			continue
		}

		cveMap := map[string]Cve{}
		for _, c := range ovaldef.Advisory.Cves {
			cveMap[c.CveID] = Cve{
				CveID: c.CveID,
				Href:  c.Href,
			}
		}

		rs := []Reference{}
		for _, r := range ovaldef.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})

			if r.Source == "CVE" {
				if _, ok := cveMap[r.RefID]; !ok {
					cveMap[r.RefID] = Cve{
						CveID: r.RefID,
						Href:  r.RefURL,
					}
				}
			}
		}

		cves := []Cve{}
		for _, cve := range cveMap {
			cves = append(cves, cve)
		}

		osVerPacks := map[string][]Package{}
		for _, distPack := range collectOraclePacks(ovaldef.Criteria) {
			osVerPacks[distPack.osVer] = append(osVerPacks[distPack.osVer], distPack.pack)
		}

		for osVer, packs := range osVerPacks {
			def := Definition{
				DefinitionID: ovaldef.ID,
				Title:        strings.TrimSpace(ovaldef.Title),
				Description:  strings.TrimSpace(ovaldef.Description),
				Advisory: Advisory{
					Severity:        ovaldef.Advisory.Severity,
					Cves:            append([]Cve{}, cves...),
					Bugzillas:       []Bugzilla{},
					AffectedCPEList: []Cpe{},
					Issued:          time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
					Updated:         time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
				Debian:        Debian{},
				AffectedPacks: append([]Package{}, packs...),
				References:    append([]Reference{}, rs...),
			}

			if viper.GetBool("no-details") {
				def.Title = ""
				def.Description = ""
				def.Advisory.Severity = ""
				def.Advisory.Bugzillas = []Bugzilla{}
				def.Advisory.AffectedCPEList = []Cpe{}
				def.Advisory.Issued = time.Time{}
				def.Advisory.Updated = time.Time{}
				def.References = []Reference{}
			}

			osVerDefs[osVer] = append(osVerDefs[osVer], def)
		}
	}

	return osVerDefs
}

func collectOraclePacks(cri oval.Criteria) []distroPackage {
	return walkOracle(cri, "", "", []distroPackage{})
}

func walkOracle(cri oval.Criteria, osVer, arch string, acc []distroPackage) []distroPackage {
	for _, c := range cri.Criterions {
		// <criterion test_ref="oval:com.oracle.elsa:tst:20110498001" comment="Oracle Linux 6 is installed"/>
		if strings.HasPrefix(c.Comment, "Oracle Linux ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			osVer = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Oracle Linux "), " is installed")
		}

		// <criterion test_ref="oval:com.oracle.elsa:tst:20110498002" comment="Oracle Linux arch is x86_64"/>
		const archPrefix = "Oracle Linux arch is "
		if strings.HasPrefix(c.Comment, archPrefix) {
			arch = strings.TrimSpace(strings.TrimPrefix(c.Comment, archPrefix))
		}

		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		if ss[1] == "0" {
			continue
		}
		acc = append(acc, distroPackage{
			osVer: osVer,
			pack: Package{
				Name:    ss[0],
				Version: strings.Split(ss[1], " ")[0],
				Arch:    arch,
			},
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkOracle(c, osVer, arch, acc)
	}
	return acc
}
