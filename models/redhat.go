package models

import (
	"github.com/ymomoi/goval-parser/oval"
)

// ConvertRedHatToModel Convert OVAL to models
func ConvertRedHatToModel(root *oval.Root) (defs []Definition) {
	for _, d := range root.Definitions.Definitions {
		rs := []Reference{}
		for _, r := range d.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		cl := []Cpe{}
		for _, cpe := range d.Advisory.AffectedCPEList {
			cl = append(cl, Cpe{
				Cpe: cpe,
			})
		}

		cves := []Cve{}
		for _, c := range d.Advisory.Cves {
			cves = append(cves, Cve{
				CveID:  c.CveID,
				Cvss2:  c.Cvss2,
				Cvss3:  c.Cvss3,
				Cwe:    c.Cwe,
				Href:   c.Href,
				Public: c.Public,
			})
		}

		bs := []Bugzilla{}
		for _, b := range d.Advisory.Bugzillas {
			bs = append(bs, Bugzilla{
				BugzillaID: b.ID,
				URL:        b.URL,
				Title:      b.Title,
			})
		}

		def := Definition{
			Title:       d.Title,
			Description: d.Description,
			Advisory: Advisory{
				Cves:            cves,
				Severity:        d.Advisory.Severity,
				AffectedCPEList: cl,
				Bugzillas:       bs,
			},
			AffectedPacks: collectPacks(d.Criteria),
			References:    rs,
		}
		defs = append(defs, def)
	}
	return
}
