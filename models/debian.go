package models

import (
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/util"
	"github.com/ymomoi/goval-parser/oval"
)

type distroPackage struct {
	osVer string
	pack  Package
}

// ConvertDebianToModel Convert OVAL to models
func ConvertDebianToModel(root *oval.Root) (defs []Definition) {
	for _, ovaldef := range root.Definitions.Definitions {
		if strings.Contains(ovaldef.Description, "** REJECT **") {
			continue
		}

		cves := []Cve{}
		rs := []Reference{}
		for _, r := range ovaldef.References {
			if r.Source == "CVE" {
				cves = append(cves, Cve{
					CveID: r.RefID,
					Href:  r.RefURL,
				})
			}

			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		var t time.Time
		if ovaldef.Debian.Date == "" {
			t = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
		} else {
			t = util.ParsedOrDefaultTime("2006-01-02", ovaldef.Debian.Date)
		}

		packs := []Package{}
		for _, distPack := range collectDebianPacks(ovaldef.Criteria) {
			packs = append(packs, distPack.pack)
		}

		def := Definition{
			DefinitionID: ovaldef.ID,
			Title:        ovaldef.Title,
			Description:  ovaldef.Description,
			Advisory: Advisory{
				Severity:        "",
				Cves:            cves,
				Bugzillas:       []Bugzilla{},
				AffectedCPEList: []Cpe{},
				Issued:          time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
				Updated:         time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
			},
			Debian: &Debian{
				MoreInfo: ovaldef.Debian.MoreInfo,
				Date:     t,
			},
			AffectedPacks: packs,
			References:    rs,
		}

		if viper.GetBool("no-details") {
			def.Title = ""
			def.Description = ""
			def.Advisory.Severity = ""
			def.Advisory.Bugzillas = []Bugzilla{}
			def.Advisory.AffectedCPEList = []Cpe{}
			def.Advisory.Issued = time.Time{}
			def.Advisory.Updated = time.Time{}
			def.Debian = nil
			def.References = []Reference{}
		}

		defs = append(defs, def)
	}
	return
}

func collectDebianPacks(cri oval.Criteria) []distroPackage {
	return walkDebian(cri, "", []distroPackage{})
}

func walkDebian(cri oval.Criteria, osVer string, acc []distroPackage) []distroPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Debian ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			osVer = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Debian "), " is installed")
		}
		ss := strings.Split(c.Comment, " DPKG is earlier than ")
		if len(ss) != 2 {
			continue
		}

		// "0" means notyetfixed or erroneous information.
		// Not available because "0" includes erroneous info...
		if ss[1] == "0" {
			continue
		}
		acc = append(acc, distroPackage{
			osVer: osVer,
			pack: Package{
				Name:    ss[0],
				Version: strings.Split(ss[1], " ")[0],
			},
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkDebian(c, osVer, acc)
	}
	return acc
}
