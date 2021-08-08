package models

import (
	"strings"
	"time"

	"github.com/spf13/viper"
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
		rs := []Reference{}
		for _, r := range ovaldef.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		description := ovaldef.Description
		if ovaldef.Debian.MoreInfo != "" {
			description = fmt.Sprintf("%s\n[MoreInfo]\n%s", description, ovaldef.Debian.MoreInfo)
		}

		for _, distPack := range collectDebianPacks(ovaldef.Criteria) {
			const timeformat = "2006-01-02"

			var t time.Time
			if ovaldef.Debian.Date == "" {
				t = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
			} else {
				t, _ = time.Parse(timeformat, ovaldef.Debian.Date)
			}

			def := Definition{
				DefinitionID: ovaldef.ID,
				Title:        ovaldef.Title,
				Description:  ovaldef.Description,
				Debian: Debian{
					CveID:    ovaldef.Title,
					MoreInfo: ovaldef.Debian.MoreInfo,
					Date:     t,
				},
				AffectedPacks: []Package{distPack.pack},
				References:    rs,
			}

			if viper.GetBool("no-details") {
				def.Title = ""
				def.Description = ""
				def.Advisory = Advisory{}

				var references []Reference
				for _, ref := range def.References {
					if ref.Source != "CVE" {
						continue
					}
					references = append(references, Reference{
						Source: ref.Source,
						RefID:  ref.RefID,
					})
				}
				def.Debian.MoreInfo = ""
				def.References = references
			}

			defs = append(defs, def)
		}
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
