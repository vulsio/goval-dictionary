package models

import (
	"strings"

	"github.com/ymomoi/goval-parser/oval"

	"github.com/kotakanbe/goval-dictionary/config"
	c "github.com/kotakanbe/goval-dictionary/config"
)

// ConvertOracleToModel Convert OVAL to models
func ConvertOracleToModel(root *oval.Root) (roots []Root) {
	m := map[string]Root{}

	for _, ovaldef := range root.Definitions.Definitions {
		if strings.Contains(ovaldef.Description, "** REJECT **") {
			continue
		}
		rs := []Reference{}
		for _, r := range ovaldef.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		cves := []Cve{}
		for _, c := range ovaldef.Advisory.Cves {
			cves = append(cves, Cve{
				CveID: c.CveID,
				Href:  c.Href,
			})
		}

		for _, distPack := range collectOraclePacks(ovaldef.Criteria) {
			// If the same slice is used, it will only be stored once in the DB
			copyRs := make([]Reference, len(rs))
			copy(copyRs, rs)

			copyCves := make([]Cve, len(cves))
			copy(copyCves, cves)

			def := Definition{
				DefinitionID: ovaldef.ID,
				Title:        ovaldef.Title,
				Description:  ovaldef.Description,
				Advisory: Advisory{
					Cves:     copyCves,
					Severity: ovaldef.Advisory.Severity,
				},
				AffectedPacks: []Package{distPack.pack},
				References:    copyRs,
			}

			if c.Conf.NoDetails {
				def.Title = ""
				def.Description = ""
				def.References = []Reference{}
			}

			root, ok := m[distPack.osVer]
			if ok {
				root.Definitions = append(root.Definitions, def)
				m[distPack.osVer] = root
			} else {
				m[distPack.osVer] = Root{
					Family:      config.Oracle,
					OSVersion:   distPack.osVer,
					Definitions: []Definition{def},
				}
			}
		}
	}

	for _, v := range m {
		roots = append(roots, v)
	}
	return
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
