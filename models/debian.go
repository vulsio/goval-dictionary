package models

import (
	"strings"

	"github.com/ymomoi/goval-parser/oval"
)

type distroPackage struct {
	release string
	pack    Package
}

func collectDebianPacks(cri oval.Criteria) []distroPackage {
	return walkDebian(cri, "", []distroPackage{})
}

func walkDebian(cri oval.Criteria, release string, acc []distroPackage) []distroPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Debian ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			release = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Debian "), " is installed")
		}
		ss := strings.Split(c.Comment, " DPKG is earlier than ")
		if len(ss) != 2 {
			continue
		}
		if ss[1] == "0" {
			continue
		}
		acc = append(acc, distroPackage{
			release: release,
			pack: Package{
				Name:    ss[0],
				Version: ss[1],
			},
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkDebian(c, release, acc)
	}
	return acc
}

// ConvertDebianToModel Convert OVAL to models
// return Meta
func ConvertDebianToModel(root *oval.Root) (metas []Meta) {
	m := map[string]Meta{}

	for _, ovaldef := range root.Definitions.Definitions {
		rs := []Reference{}
		for _, r := range ovaldef.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		for _, distPack := range collectDebianPacks(ovaldef.Criteria) {
			def := Definition{
				Title:         ovaldef.Title,
				Description:   ovaldef.Description,
				AffectedPacks: []Package{distPack.pack},
				References:    rs,
			}

			meta, ok := m[distPack.release]
			if ok {
				meta.Definitions = append(meta.Definitions, def)
				m[distPack.release] = meta
			} else {
				m[distPack.release] = Meta{
					Family:      "Debian",
					Release:     distPack.release,
					Definitions: []Definition{def},
				}
			}
		}
	}

	for _, v := range m {
		metas = append(metas, v)
	}
	return
}
