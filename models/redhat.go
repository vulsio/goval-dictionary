package models

import (
	"strings"
	"time"

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
				Impact: c.Impact,
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

		const timeformat = "2006-01-02"
		issued, _ := time.Parse(timeformat, d.Advisory.Issued.Date)
		updated, _ := time.Parse(timeformat, d.Advisory.Updated.Date)

		def := Definition{
			DefinitionID: d.ID,
			Title:        d.Title,
			Description:  d.Description,
			Advisory: Advisory{
				Cves:            cves,
				Severity:        d.Advisory.Severity,
				AffectedCPEList: cl,
				Bugzillas:       bs,
				Issued:          issued,
				Updated:         updated,
			},
			AffectedPacks: collectRedHatPacks(d.Criteria),
			References:    rs,
		}
		defs = append(defs, def)
	}
	return
}

func collectRedHatPacks(cri oval.Criteria) []Package {
	return walkRedHat(cri, []Package{})
}

func walkRedHat(cri oval.Criteria, acc []Package) []Package {
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
		acc = walkRedHat(c, acc)
	}
	return acc
}
