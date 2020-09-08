package models

import (
	"fmt"
	"strings"

	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/ymomoi/goval-parser/oval"
)

// ConvertSUSEToModel Convert OVAL to models
func ConvertSUSEToModel(root *oval.Root, suseType string) (defs []Definition) {
	for _, d := range root.Definitions.Definitions {
		rs := []Reference{}
		for _, r := range d.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		def := Definition{
			DefinitionID:  d.ID,
			Title:         d.Title,
			Description:   d.Description,
			AffectedPacks: collectSUSEPacks(d.Criteria),
			References:    rs,
		}

		if c.Conf.NoDetails {
			def.Title = ""
			def.Description = ""
			def.Advisory = Advisory{}

			var references []Reference
			for _, ref := range def.References {
				if ref.Source != "CVE" {
					continue
				}
				references = append(references, Reference{
					Source: ref.Source,
					RefID:  ref.RefID,
				})
			}
			def.References = references
		}

		defs = append(defs, def)
	}
	return
}

func collectSUSEPacks(cri oval.Criteria) []Package {
	return walkSUSE(cri, []Package{})
}

func walkSUSE(cri oval.Criteria, acc []Package) []Package {
	for _, c := range cri.Criterions {
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

		acc = append(acc, Package{
			Name:    name,
			Version: version,
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
