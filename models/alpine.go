package models

import (
	"strings"
)

// AlpineSecDB is a struct of alpine secdb
type AlpineSecDB struct {
	Distroversion string
	Reponame      string
	Urlprefix     string
	Apkurl        string
	Packages      []struct {
		Pkg struct {
			Name     string
			Secfixes map[string][]string
		}
	}
}

// ConvertAlpineToModel Convert OVAL to models
func ConvertAlpineToModel(data *AlpineSecDB) (defs []Definition) {
	cveIDPacks := map[string][]Package{}
	for _, pack := range data.Packages {
		for ver, vulnIDs := range pack.Pkg.Secfixes {
			for _, s := range vulnIDs {
				cveID := strings.Split(s, " ")[0]
				if !strings.HasPrefix(cveID, "CVE") {
					continue
				}

				if packs, ok := cveIDPacks[cveID]; ok {
					packs = append(packs, Package{
						Name:    pack.Pkg.Name,
						Version: ver,
					})
					cveIDPacks[cveID] = packs
				} else {
					cveIDPacks[cveID] = []Package{{
						Name:    pack.Pkg.Name,
						Version: ver,
					}}
				}
			}
		}
	}

	for cveID, packs := range cveIDPacks {
		def := Definition{
			Advisory: Advisory{
				Cves: []Cve{{CveID: cveID}},
			},
			AffectedPacks: packs,
		}
		defs = append(defs, def)
	}
	return
}
