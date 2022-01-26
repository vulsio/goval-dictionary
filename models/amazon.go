package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/fetcher"
	"github.com/vulsio/goval-dictionary/util"
)

// ConvertAmazonToModel Convert OVAL to models
func ConvertAmazonToModel(data *fetcher.AmazonUpdates) (defs []Definition) {
	for _, alas := range data.UpdateList {
		if strings.Contains(alas.Description, "** REJECT **") {
			continue
		}

		cves := []Cve{}
		for _, cveID := range alas.CVEIDs {
			cves = append(cves, Cve{
				CveID: cveID,
				Href:  fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID),
			})
		}

		packs := []Package{}
		for _, pack := range alas.Packages {
			packs = append(packs, Package{
				Name:    pack.Name,
				Version: fmt.Sprintf("%s:%s-%s", pack.Epoch, pack.Version, pack.Release),
				Arch:    pack.Arch,
			})
		}
		updatedAt := util.ParsedOrDefaultTime("2006-01-02 15:04", alas.Updated.Date)

		refs := []Reference{}
		for _, ref := range alas.References {
			refs = append(refs, Reference{
				Source: ref.Type,
				RefID:  ref.ID,
				RefURL: ref.Href,
			})
		}

		def := Definition{
			DefinitionID: "def-" + alas.ID,
			Title:        alas.ID,
			Description:  alas.Description,
			Advisory: Advisory{
				Severity:        alas.Severity,
				Cves:            cves,
				Bugzillas:       []Bugzilla{},
				AffectedCPEList: []Cpe{},
				Issued:          time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
				Updated:         updatedAt,
			},
			Debian:        nil,
			AffectedPacks: packs,
			References:    refs,
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
