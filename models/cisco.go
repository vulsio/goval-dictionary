package models

import (
	"strings"

	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/ymomoi/goval-parser/oval"
)

// ConvertCiscoToModel Convert OVAL to models
func ConvertCiscoToModel(root *oval.Root) (defs []Definition) {
	for _, d := range root.Definitions.Definitions {

		cveID := ""
		rs := []Reference{}
		for _, r := range d.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
			if r.Source == "CVE" {
				cveID = r.RefID
			}
		}

		def := Definition{
			DefinitionID: d.ID,
			Title:        d.Title,
			Description:  d.Description,
			Advisory: Advisory{
				Cves: []Cve{{CveID: cveID}},
			},
			References: rs,
			AffectedPacks: collectCiscoPacks(d.Criteria),
		}

		if c.Conf.NoDetails {
			def.Title = ""
			def.Description = ""
			def.Advisory = Advisory{}
			def.References = []Reference{}
		}

		defs = append(defs, def)
	}
	return
}

func collectCiscoPacks(cri oval.Criteria) []Package {
	return walkCisco(cri, []Package{})
}

func walkCisco(cri oval.Criteria, acc []Package) []Package {
	for _, c := range cri.Criterions {
		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		acc = append(acc, Package{
			Name:    ss[0],
			Version: strings.Split(ss[1], " ")[0],
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkCisco(c, acc)
	}
	return acc
}
