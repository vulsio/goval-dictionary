package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
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
			DefinitionID: fmt.Sprintf("def-%s-%s-%s", data.Reponame, data.Distroversion, cveID),
			Title:        cveID,
			Description:  "",
			Advisory: Advisory{
				Severity:        "",
				Cves:            []Cve{{CveID: cveID, Href: fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID)}},
				Bugzillas:       []Bugzilla{},
				AffectedCPEList: []Cpe{},
				Issued:          time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
				Updated:         time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
			},
			Debian:        nil,
			AffectedPacks: packs,
			References: []Reference{
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
			def.Advisory.Bugzillas = []Bugzilla{}
			def.Advisory.AffectedCPEList = []Cpe{}
			def.Advisory.Issued = time.Time{}
			def.Advisory.Updated = time.Time{}
			def.References = []Reference{}
		}

		defs = append(defs, def)
	}
	return
}
