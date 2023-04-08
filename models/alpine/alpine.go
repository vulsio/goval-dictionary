package alpine

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/vulsio/goval-dictionary/models"
)

func (p PackageType1) extractCveIdPackages() []CveIdPackage {
	cveIDPacks := []CveIdPackage{}
	for ver, vulnIDs := range p.Pkg.Secfixes {
		for _, s := range vulnIDs {
			cveID := strings.Split(s, " ")[0]
			if !strings.HasPrefix(cveID, "CVE") {
				continue
			}

			cveIDPacks = append(cveIDPacks, CveIdPackage{CveId: cveID, Package: models.Package{
				Name:    p.Pkg.Name,
				Version: ver,
			}})
		}
	}
	return cveIDPacks
}

func (p PackageType2) extractCveIdPackages() []CveIdPackage {
	cveIDPacks := []CveIdPackage{}
	for _, secFix := range p.Pkg.Secfixes {
		for _, fix := range secFix.Fixes {
			for _, s := range fix.Identifiers {
				cveID := strings.Split(s, " ")[0]
				if !strings.HasPrefix(cveID, "CVE") {
					continue
				}

				cveIDPacks = append(cveIDPacks, CveIdPackage{CveId: cveID, Package: models.Package{
					Name:    p.Pkg.Name,
					Version: secFix.Version,
				}})
			}
		}
	}
	return cveIDPacks
}

// ConvertToModel Convert OVAL to models
func ConvertToModel[T PackageType](data *SecDB[T]) (defs []models.Definition) {
	packs := []CveIdPackage{}
	for _, pack := range data.Packages {
		packs = append(packs, pack.extractCveIdPackages()...)
	}

	cveIDPacks := map[string][]models.Package{}
	for _, pack := range packs {
		if packs, ok := cveIDPacks[pack.CveId]; ok {
			packs = append(packs, pack.Package)
			cveIDPacks[pack.CveId] = packs
		} else {
			cveIDPacks[pack.CveId] = []models.Package{pack.Package}
		}
	}

	for cveID, packs := range cveIDPacks {
		def := models.Definition{
			DefinitionID: fmt.Sprintf("def-%s-%s-%s", data.Reponame, data.Distroversion, cveID),
			Title:        cveID,
			Description:  "",
			Advisory: models.Advisory{
				Severity:        "",
				Cves:            []models.Cve{{CveID: cveID, Href: fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID)}},
				Bugzillas:       []models.Bugzilla{},
				AffectedCPEList: []models.Cpe{},
				Issued:          time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
				Updated:         time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
			},
			Debian:        nil,
			AffectedPacks: packs,
			References: []models.Reference{
				{
					Source: "CVE",
					RefID:  cveID,
					RefURL: fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID),
				},
			},
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

		defs = append(defs, def)
	}
	return
}
