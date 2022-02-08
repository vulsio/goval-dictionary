package redhat

import (
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
		for _, c := range d.Advisory.Cves {
			cves = append(cves, models.Cve{
				CveID:  c.CveID,
				Cvss2:  c.Cvss2,
				Cvss3:  c.Cvss3,
				Cwe:    c.Cwe,
				Impact: c.Impact,
				Href:   c.Href,
				Public: c.Public,
			})
		}

		rs := []models.Reference{}
		for _, r := range d.References {
			rs = append(rs, models.Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		cl := []models.Cpe{}
		for _, cpe := range d.Advisory.AffectedCPEList {
			cl = append(cl, models.Cpe{
				Cpe: cpe,
			})
		}

		bs := []models.Bugzilla{}
		for _, b := range d.Advisory.Bugzillas {
			bs = append(bs, models.Bugzilla{
				BugzillaID: b.ID,
				URL:        b.URL,
				Title:      b.Title,
			})
		}

		const timeformat = "2006-01-02"
		issued := util.ParsedOrDefaultTime(timeformat, d.Advisory.Issued.Date)
		updated := util.ParsedOrDefaultTime(timeformat, d.Advisory.Updated.Date)

		def := models.Definition{
			DefinitionID: d.ID,
			Title:        d.Title,
			Description:  d.Description,
			Advisory: models.Advisory{
				Severity:        d.Advisory.Severity,
				Cves:            cves,
				Bugzillas:       bs,
				AffectedCPEList: cl,
				Issued:          issued,
				Updated:         updated,
			},
			Debian:        nil,
			AffectedPacks: collectRedHatPacks(d.Criteria),
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

func collectRedHatPacks(cri Criteria) []models.Package {
	return walkRedHat(cri, []models.Package{}, "")
}

func walkRedHat(cri Criteria, acc []models.Package, label string) []models.Package {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Module ") && strings.HasSuffix(c.Comment, " is enabled") {
			label = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Module "), " is enabled")
		}

		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		acc = append(acc, models.Package{
			Name:            ss[0],
			Version:         strings.Split(ss[1], " ")[0],
			ModularityLabel: label,
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkRedHat(c, acc, label)
	}
	return acc
}
