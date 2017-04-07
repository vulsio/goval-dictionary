package models

import (
	"strings"

	"github.com/ymomoi/goval-parser/oval"
)

// ConvertRedHatToModel Convert OVAL to models
func ConvertRedHatToModel(root oval.Root) (defs []Definition) {
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
			Title:       d.Title,
			Description: d.Description,
			Advisory: Advisory{
				CveID:           d.Advisory.CveID,
				Severity:        d.Advisory.Severity,
				AffectedCPEList: d.Advisory.AffectedCPEList,
				Bugzilla: Bugzilla{
					BugzillaID: d.Advisory.Bugzilla.ID,
					URL:        d.Advisory.Bugzilla.URL,
					Title:      d.Advisory.Bugzilla.Title,
				},
			},
			AffectedPacks: collectPacks(d.Criteria),
			References:    rs,
		}
		defs = append(defs, def)
	}
	return
}

func collectPacks(cri oval.Criteria) []Package {
	return walk(cri, []Package{})
}

func walk(cri oval.Criteria, acc []Package) []Package {
	for _, c := range cri.Criterions {
		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		acc = append(acc, Package{
			Name:    ss[0],
			Version: ss[1],
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walk(*c, acc)
	}
	return acc
}
