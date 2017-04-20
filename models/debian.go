package models

import (
	"strings"
	"time"

	"github.com/ymomoi/goval-parser/oval"
)

type distroPackage struct {
	release string
	pack    Package
}

// ConvertDebianToModel Convert OVAL to models
func ConvertDebianToModel(root *oval.Root) (roots []Root) {
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

		for _, distPack := range collectDebianPacks(ovaldef.Criteria) {
			const timeformat = "2006-01-02"
			t, _ := time.Parse(timeformat, ovaldef.Debian.Date)

			def := Definition{
				Title:       ovaldef.Title,
				Description: ovaldef.Description,
				Debian: Debian{
					CveID:    ovaldef.Title,
					MoreInfo: ovaldef.Debian.MoreInfo,
					Date:     t,
				},
				AffectedPacks: []Package{distPack.pack},
				References:    rs,
			}

			root, ok := m[distPack.release]
			if ok {
				root.Definitions = append(root.Definitions, def)
				m[distPack.release] = root
			} else {
				m[distPack.release] = Root{
					Family:      "Debian",
					Release:     distPack.release,
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
				Version: strings.Split(ss[1], " ")[0],
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
