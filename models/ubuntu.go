package models

import (
	"regexp"

	c "github.com/kotakanbe/goval-dictionary/config"
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

func collectUbuntuPacks(cri oval.Criteria) []Package {
	return walkUbuntu(cri, []Package{})
}

func walkUbuntu(cri oval.Criteria, acc []Package) []Package {
	for _, c := range cri.Criterions {
		if c.Negate {
			continue
		}

		if pkg, ok := parseNotFixedYet(c.Comment); ok {
			acc = append(acc, *pkg)
		}
		if pkg, ok := parseNotDecided(c.Comment); ok {
			acc = append(acc, *pkg)
		}
		if pkg, ok := parseFixed(c.Comment); ok {
			acc = append(acc, *pkg)
		}

		// nop for now
		// <criterion test_ref="oval:com.ubuntu.xenial:tst:10" comment="The vulnerability of the 'brotli' package in xenial is not known (status: 'needs-triage'). It is pending evaluation." />
		// <criterion test_ref="oval:com.ubuntu.bionic:tst:201211480000000" comment="apache2: while related to the CVE in some way, a decision has been made to ignore this issue (note: 'code-not-compiled')." />

	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkUbuntu(c, acc)
	}
	return acc
}

var reNotFixed = regexp.MustCompile(`^(.+) package in .+ affected and needs fixing.$`)

func parseNotFixedYet(comment string) (*Package, bool) {
	// <criterion test_ref="oval:com.ubuntu.bionic:tst:200702550000000" comment="xine-console package in bionic is affected and needs fixing." />
	res := reNotFixed.FindStringSubmatch(comment)
	if len(res) == 2 {
		return &Package{
			Name:        res[1],
			NotFixedYet: true,
		}, true
	}
	return nil, false
}

var reNotDecided = regexp.MustCompile(`^(.+) package in .+ is affected, but a decision has been made to defer addressing it .+$`)

func parseNotDecided(comment string) (*Package, bool) {
	// <criterion test_ref="oval:com.ubuntu.bionic:tst:201208800000000" comment="libxerces-c-samples package in bionic is affected, but a decision has been made to defer addressing it (note: '2019-01-01')." />
	res := reNotDecided.FindStringSubmatch(comment)
	if len(res) == 2 {
		return &Package{
			Name:        res[1],
			NotFixedYet: true,
		}, true
	}
	return nil, false
}

var reFixed = regexp.MustCompile(`^(.+) package in .+ has been fixed \(note: '(.+)'\).$`)

func parseFixed(comment string) (*Package, bool) {
	// <criterion test_ref="oval:com.ubuntu.bionic:tst:201210880000000" comment="iproute2 package in bionic, is related to the CVE in some way and has been fixed (note: '3.12.0-2')." />
	res := reFixed.FindStringSubmatch(comment)
	if len(res) == 3 {
		return &Package{
			Name:    res[1],
			Version: res[2],
		}, true
	}
	return nil, false
}
