package models

import (
	"regexp"

	"github.com/ymomoi/goval-parser/oval"
)

// ConvertUbuntuToModel Convert OVAL to models
func ConvertUbuntuToModel(root *oval.Root) (defs []Definition) {
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

		for _, r := range d.Advisory.Refs {
			rs = append(rs, Reference{
				Source: "Ref",
				RefURL: r.URL,
			})
		}

		for _, r := range d.Advisory.Bugs {
			rs = append(rs, Reference{
				Source: "Bug",
				RefURL: r.URL,
			})
		}

		def := Definition{
			DefinitionID: d.ID,
			Title:        d.Title,
			Description:  d.Description,
			Advisory: Advisory{
				Severity: d.Advisory.Severity,
			},
			Debian:        Debian{CveID: cveID},
			AffectedPacks: collectUbuntuPacks(d.Criteria),
			References:    rs,
		}
		defs = append(defs, def)
	}
	return
}

func collectUbuntuPacks(cri oval.Criteria) []Package {
	return walkUbuntu(cri, []Package{})
}

var reFixed = regexp.MustCompile(`^The '(.+)' package in .* was vulnerable but has been fixed \(note: '(.+)'\).$`)
var reNotFixed = regexp.MustCompile(`^The '(.+)' package in .* is affected and needs fixing.$`)
var reNotDecided = regexp.MustCompile(`^The '(.+)' package in .* is affected, but a decision has been made to defer addressing it.*$`)

func walkUbuntu(cri oval.Criteria, acc []Package) []Package {
	for _, c := range cri.Criterions {
		if c.Negate {
			continue
		}

		// <criterion comment="The 'linux-flo' package in xenial is affected and needs fixing." />
		//  ss := strings.Split(c.Comment, " is earlier than ")
		res := reNotFixed.FindStringSubmatch(c.Comment)
		if len(res) == 2 {
			acc = append(acc, Package{
				Name:        res[1],
				NotFixedYet: true,
			})
			continue
		}

		// <criterion comment="The 'tiff' package in xenial is affected, but a decision has been made to defer addressing it (note: '2017-02-24')." />
		res = reNotDecided.FindStringSubmatch(c.Comment)
		if len(res) == 2 {
			acc = append(acc, Package{
				Name:        res[1],
				NotFixedYet: true,
			})
			continue
		}

		// <criterion comment="The 'poppler' package in xenial was vulnerable but has been fixed (note: '0.12.2-2.1ubuntu1')." />
		res = reFixed.FindStringSubmatch(c.Comment)
		if len(res) == 3 {
			acc = append(acc, Package{
				Name:    res[1],
				Version: res[2],
			})
			continue
		}

		// <criterion test_ref="oval:com.ubuntu.xenial:tst:10" comment="The vulnerability of the 'brotli' package in xenial is not known (status: 'needs-triage'). It is pending evaluation." />
		// nop for now
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkUbuntu(c, acc)
	}
	return acc
}
