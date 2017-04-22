package models

import (
	"fmt"
	"strings"

	"github.com/k0kubun/pp"
	"github.com/ymomoi/goval-parser/oval"
)

// ConvertSUSEToModel Convert OVAL to models
func ConvertSUSEToModel(root *oval.Root) (defs []Definition) {
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
				Title:         ovaldef.Title,
				Description:   ovaldef.Description,
				AffectedPacks: []Package{distPack.pack},
				References:    rs,
			}
			defs = append(defs, def)
		}
	}
	return
}

func collectSUSEPacks(cri oval.Criteria) []distroPackage {
	return walkSUSE(cri, []distroPackage{})
}

func walkSUSE(cri oval.Criteria, acc []distroPackage) []distroPackage {
	for _, c := range cri.Criterions {
		var packVer string
		if strings.HasPrefix(c.Comment, "SUSE ") ||
			strings.HasPrefix(c.Comment, "openSUSE ") {
			continue
		}

		if strings.HasSuffix(c.Comment, " is installed") {
			packVer = strings.TrimSuffix(c.Comment, " is installed")
		}

		ss := strings.Split(packVer, "-")
		if len(ss) < 3 {
			//TODO Remove
			pp.Printf("NG %s", packVer)
			continue
		}

		name := fmt.Sprintf("%s", strings.Join(ss[0:len(ss)-2], "-"))
		version := fmt.Sprintf("%s-%s", ss[len(ss)-2], ss[len(ss)-1])

		acc = append(acc, distroPackage{
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
		acc = walkSUSE(c, acc)
	}
	return acc
}
