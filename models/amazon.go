package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/spf13/viper"
)

// ConvertAmazonToModel Convert OVAL to models
func ConvertAmazonToModel(data *fetcher.UpdateInfo) (defs []Definition) {
	for _, alas := range data.ALASList {
		if strings.Contains(alas.Description, "** REJECT **") {
			continue
		}
		cves := []Cve{}
		for _, cveID := range alas.CVEIDs {
			cves = append(cves, Cve{CveID: cveID})
		}

		packs := []Package{}
		for _, pack := range alas.Packages {
			packs = append(packs, Package{
				Name: pack.Name,
				Version: fmt.Sprintf("%s:%s-%s",
					pack.Epoch, pack.Version, pack.Release),
				Arch: pack.Arch,
			})
		}
		updatedAt, _ := time.Parse("2006-01-02 15:04", alas.Updated.Date)

		refs := []Reference{}
		for _, ref := range alas.References {
			refs = append(refs, Reference{
				Source: ref.Type,
				RefID:  ref.ID,
				RefURL: ref.Href,
			})
		}

		def := Definition{
			DefinitionID:  "def-" + alas.ID,
			Title:         alas.ID,
			Description:   alas.Description,
			AffectedPacks: packs,
			Advisory: Advisory{
				Cves:     cves,
				Severity: alas.Severity,
				Issued:   time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
				Updated:  updatedAt,
			},
			References: refs,
		}

		if viper.GetBool("no-details") {
			def.Description = ""
			def.References = []Reference{}
		}

		defs = append(defs, def)
	}
	return
}
