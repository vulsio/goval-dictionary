package models

import (
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/ymomoi/goval-parser/oval"
)

var cveIDPattern = regexp.MustCompile(`(CVE-\d{4}-\d{4,})`)

// ConvertRedHatToModel Convert OVAL to models
func ConvertRedHatToModel(root *oval.Root) (defs []Definition) {
	for _, d := range root.Definitions.Definitions {
		if strings.Contains(d.Description, "** REJECT **") {
			continue
		}

		cveMap := map[string]Cve{}
		for _, c := range d.Advisory.Cves {
			cveMap[c.CveID] = Cve{
				CveID:  c.CveID,
				Cvss2:  c.Cvss2,
				Cvss3:  c.Cvss3,
				Cwe:    c.Cwe,
				Impact: c.Impact,
				Href:   c.Href,
				Public: c.Public,
			}
		}

		rs := []Reference{}
		for _, r := range d.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})

			if r.Source == "CVE" {
				if _, ok := cveMap[r.RefID]; !ok {
					cveMap[r.RefID] = Cve{
						CveID: r.RefID,
						Href:  r.RefURL,
					}
				}
			}
		}

		cl := []Cpe{}
		for _, cpe := range d.Advisory.AffectedCPEList {
			cl = append(cl, Cpe{
				Cpe: cpe,
			})
		}

		cves := []Cve{}
		for _, cve := range cveMap {
			cves = append(cves, cve)
		}

		bs := []Bugzilla{}
		for _, b := range d.Advisory.Bugzillas {
			bs = append(bs, Bugzilla{
				BugzillaID: b.ID,
				URL:        b.URL,
				Title:      b.Title,
			})
		}

		if len(cves) == 0 {
			for _, b := range d.Advisory.Bugzillas {
				fields := strings.Fields(b.Title)
				if len(fields) > 0 && cveIDPattern.MatchString(fields[0]) {
					cves = append(cves, Cve{CveID: fields[0]})
				}
			}
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

		if viper.GetBool("no-details") {
			def.Title = ""
			def.Description = ""
			def.Advisory.Severity = ""
			def.Advisory.AffectedCPEList = []Cpe{}
			def.Advisory.Bugzillas = []Bugzilla{}
			def.Advisory.Issued = time.Time{}
			def.Advisory.Updated = time.Time{}
			def.References = []Reference{}
		}

		defs = append(defs, def)
	}
	return
}

func collectRedHatPacks(cri oval.Criteria) []Package {
	return walkRedHat(cri, []Package{}, "")
}

func walkRedHat(cri oval.Criteria, acc []Package, label string) []Package {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Module ") && strings.HasSuffix(c.Comment, " is enabled") {
			label = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Module "), " is enabled")
		}

		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		acc = append(acc, Package{
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
