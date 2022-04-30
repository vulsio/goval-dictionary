package oracle

import (
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/vulsio/goval-dictionary/models"
)

type distroPackage struct {
	osVer string
	pack  models.Package
}

// ConvertToModel Convert OVAL to models
func ConvertToModel(root *Root) (defs map[string][]models.Definition) {
	osVerDefs := map[string][]models.Definition{}
	for _, ovaldef := range root.Definitions.Definitions {
		if strings.Contains(ovaldef.Description, "** REJECT **") {
			continue
		}

		cves := []models.Cve{}
		for _, c := range ovaldef.Advisory.Cves {
			cves = append(cves, models.Cve{
				CveID: c.CveID,
				Href:  c.Href,
			})
		}

		rs := []models.Reference{}
		for _, r := range ovaldef.References {
			rs = append(rs, models.Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		osVerPacks := map[string][]models.Package{}
		for _, distPack := range collectOraclePacks(ovaldef.Criteria) {
			osVerPacks[distPack.osVer] = append(osVerPacks[distPack.osVer], distPack.pack)
		}

		for osVer, packs := range osVerPacks {
			def := models.Definition{
				DefinitionID: ovaldef.ID,
				Title:        strings.TrimSpace(ovaldef.Title),
				Description:  strings.TrimSpace(ovaldef.Description),
				Advisory: models.Advisory{
					Severity:        ovaldef.Advisory.Severity,
					Cves:            append([]models.Cve{}, cves...), // If the same slice is used, it will only be stored once in the DB
					Bugzillas:       []models.Bugzilla{},
					AffectedCPEList: []models.Cpe{},
					Issued:          time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
					Updated:         time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
				Debian:        nil,
				AffectedPacks: append([]models.Package{}, packs...), // If the same slice is used, it will only be stored once in the DB
				References:    append([]models.Reference{}, rs...),  // If the same slice is used, it will only be stored once in the DB
			}

			if viper.GetBool("no-details") {
				def.Title = ""
				def.Description = ""
				def.Advisory.Severity = ""
				def.Advisory.Bugzillas = []models.Bugzilla{}
				def.Advisory.AffectedCPEList = []models.Cpe{}
				def.Advisory.Issued = time.Time{}
				def.Advisory.Updated = time.Time{}
				def.References = []models.Reference{}
			}

			osVerDefs[osVer] = append(osVerDefs[osVer], def)
		}
	}

	return osVerDefs
}

func collectOraclePacks(cri Criteria) []distroPackage {
	return walkOracle(cri, "", "", []distroPackage{})
}

func walkOracle(cri Criteria, osVer, arch string, acc []distroPackage) []distroPackage {
	for _, c := range cri.Criterions {
		// <criterion test_ref="oval:com.oracle.elsa:tst:20110498001" comment="Oracle Linux 6 is installed"/>
		if strings.HasPrefix(c.Comment, "Oracle Linux ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			osVer = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Oracle Linux "), " is installed")
		}

		// <criterion test_ref="oval:com.oracle.elsa:tst:20110498002" comment="Oracle Linux arch is x86_64"/>
		const archPrefix = "Oracle Linux arch is "
		if strings.HasPrefix(c.Comment, archPrefix) {
			arch = strings.TrimSpace(strings.TrimPrefix(c.Comment, archPrefix))
		}

		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		if ss[1] == "0" {
			continue
		}
		acc = append(acc, distroPackage{
			osVer: osVer,
			pack: models.Package{
				Name:    ss[0],
				Version: strings.Split(ss[1], " ")[0],
				Arch:    arch,
			},
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkOracle(c, osVer, arch, acc)
	}
	return acc
}
