package ubuntu

import (
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/models/util"
)

// ConvertToModel Convert OVAL to models
func ConvertToModel(root *Root) (defs []models.Definition) {
	for _, d := range root.Definitions.Definitions {
		if strings.Contains(d.Description, "** REJECT **") {
			continue
		}

		cves := []models.Cve{}
		rs := []models.Reference{}
		for _, r := range d.References {
			if r.Source == "CVE" {
				cves = append(cves, models.Cve{
					CveID: r.RefID,
					Href:  r.RefURL,
				})
			}

			rs = append(rs, models.Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		for _, r := range d.Advisory.Refs {
			rs = append(rs, models.Reference{
				Source: "Ref",
				RefURL: r.URL,
			})
		}

		for _, r := range d.Advisory.Bugs {
			rs = append(rs, models.Reference{
				Source: "Bug",
				RefURL: r.URL,
			})
		}

		var date time.Time
		if strings.HasSuffix(d.Advisory.PublicDate, "UTC") {
			date = util.ParsedOrDefaultTime("2006-01-02 15:04:05 UTC", d.Advisory.PublicDate)
		} else {
			date = util.ParsedOrDefaultTime("2006-01-02", d.Advisory.PublicDate)
		}

		def := models.Definition{
			DefinitionID: d.ID,
			Title:        d.Title,
			Description:  d.Description,
			Advisory: models.Advisory{
				Severity:        d.Advisory.Severity,
				Cves:            cves,
				Bugzillas:       []models.Bugzilla{},
				AffectedCPEList: []models.Cpe{},
				Issued:          date,
				Updated:         date,
			},
			Debian:        nil,
			AffectedPacks: collectUbuntuPacks(d.Criteria),
			References:    rs,
		}

		if viper.GetBool("no-details") {
			def.Title = ""
			def.Description = ""
			def.Advisory.Severity = ""
			def.Advisory.AffectedCPEList = []models.Cpe{}
			def.Advisory.Bugzillas = []models.Bugzilla{}
			def.Advisory.Issued = time.Time{}
			def.Advisory.Updated = time.Time{}
			def.References = []models.Reference{}
		}

		defs = append(defs, def)
	}
	return
}

func collectUbuntuPacks(cri Criteria) []models.Package {
	return walkUbuntu(cri, []models.Package{})
}

func walkUbuntu(cri Criteria, acc []models.Package) []models.Package {
	for _, c := range cri.Criterions {
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

func parseNotFixedYet(comment string) (*models.Package, bool) {
	// Ubuntu 14
	// The 'php-openid' package in trusty is affected and needs fixing.

	// Ubuntu 16, 18
	// xine-console package in bionic is affected and needs fixing. />
	res := reNotFixed.FindStringSubmatch(comment)
	if len(res) == 2 {
		return &models.Package{
			Name:        trimPkgName(res[1]),
			NotFixedYet: true,
		}, true
	}
	return nil, false
}

var reNotDecided = regexp.MustCompile(`^(.+) package in .+ is affected, but a decision has been made to defer addressing it.*$`)

func parseNotDecided(comment string) (*models.Package, bool) {
	// Ubuntu 14
	// The 'ruby1.9.1' package in trusty is affected, but a decision has been made to defer addressing it (note: '2019-04-10').

	// Ubuntu 16, 18
	// libxerces-c-samples package in bionic is affected, but a decision has been made to defer addressing it (note: '2019-01-01').
	res := reNotDecided.FindStringSubmatch(comment)
	if len(res) == 2 {
		return &models.Package{
			Name:        trimPkgName(res[1]),
			NotFixedYet: true,
		}, true
	}
	return nil, false
}

var reFixed = regexp.MustCompile(`^(.+) package in .+ has been fixed \(note: '([^\s]+).*'\).$`)

func parseFixed(comment string) (*models.Package, bool) {
	// https://github.com/vulsio/goval-dictionary/issues/120
	if strings.HasSuffix(comment, " only').") {
		return nil, false
	}

	// Ubuntu 14
	// The 'poppler' package in trusty was vulnerable but has been fixed (note: '0.10.5-1ubuntu2').

	// Ubuntu 16, 18
	// iproute2 package in bionic, is related to the CVE in some way and has been fixed (note: '3.12.0-2').
	res := reFixed.FindStringSubmatch(comment)
	if len(res) == 3 {
		return &models.Package{
			Name:    trimPkgName(res[1]),
			Version: res[2],
		}, true
	}
	return nil, false
}

func trimPkgName(name string) string {
	name = strings.TrimPrefix(name, "The '")
	return strings.TrimSuffix(name, "'")
}
