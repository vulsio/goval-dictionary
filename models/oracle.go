package models

import (
	"strings"

	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/ymomoi/goval-parser/oval"
)

// ConvertOracleToModel Convert OVAL to models
func ConvertOracleToModel(root *oval.Root) (roots []Root) {
	m := map[string]Root{}

	for _, ovaldef := range root.Definitions.Definitions {
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
			def := Definition{
				DefinitionID: ovaldef.ID,
				Title:        ovaldef.Title,
				Description:  ovaldef.Description,
				Advisory: Advisory{
					Cves:     cves,
					Severity: ovaldef.Advisory.Severity,
				},
				AffectedPacks: []Package{distPack.pack},
				References:    rs,
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
	return walkOracle(cri, "", []distroPackage{})
}

func walkOracle(cri oval.Criteria, osVer string, acc []distroPackage) []distroPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Oracle Linux ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			osVer = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Oracle Linux "), " is installed")
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
			},
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkOracle(c, osVer, acc)
	}
	return acc
}
