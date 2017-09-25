package models

import (
	"fmt"
	"strings"

	"github.com/ymomoi/goval-parser/oval"
)

// ConvertSUSEToModel Convert OVAL to models
func ConvertSUSEToModel(root *oval.Root, suseType string) (roots []Root) {
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

		for _, distPack := range collectSUSEPacks(ovaldef.Criteria) {
			def := Definition{
				DefinitionID:  ovaldef.ID,
				Title:         ovaldef.Title,
				Description:   ovaldef.Description,
				AffectedPacks: []Package{distPack.pack},
				References:    rs,
			}

			root, ok := m[distPack.osVer]
			if ok {
				root.Definitions = append(root.Definitions, def)
				m[distPack.osVer] = root
			} else {
				m[distPack.osVer] = Root{
					Family:      suseType,
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

func collectSUSEPacks(cri oval.Criteria) []distroPackage {
	return walkSUSE(cri, "", []distroPackage{})
}

func walkSUSE(cri oval.Criteria, osVer string, acc []distroPackage) []distroPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "openSUSE ") {
			continue
		}
		if strings.HasPrefix(c.Comment, "SUSE Linux Enterprise Server ") {
			osVer = strings.TrimPrefix(strings.TrimSuffix(c.Comment, " is installed"),
				"SUSE Linux Enterprise Server ")
			continue
		}

		// Ignore except SUSE Enterprise Linux and openSUSE for now.
		if strings.HasPrefix(c.Comment, "SUSE") {
			return acc
		}

		osVer = strings.TrimSuffix(osVer, "-LTSS")
		osVer = strings.Replace(osVer, " SP", ".", -1)

		packVer := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			packVer = strings.TrimSuffix(c.Comment, " is installed")
		}

		ss := strings.Split(packVer, "-")
		if len(ss) < 3 {
			continue
		}

		name := fmt.Sprintf("%s", strings.Join(ss[0:len(ss)-2], "-"))
		version := fmt.Sprintf("%s-%s", ss[len(ss)-2], ss[len(ss)-1])

		acc = append(acc, distroPackage{
			osVer: osVer,
			pack: Package{
				Name:    name,
				Version: version,
			},
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkSUSE(c, osVer, acc)
	}
	return acc
}
