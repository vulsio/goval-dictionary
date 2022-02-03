package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/fetcher"
	"github.com/vulsio/goval-dictionary/util"
)

// ConvertFedoraToModel Convert OVAL to models
func ConvertFedoraToModel(data *fetcher.FedoraUpdates) (defs []Definition) {
	for _, update := range data.UpdateList {
		if strings.Contains(update.Description, "** REJECT **") {
			continue
		}

		cves := []Cve{}
		for _, cveID := range update.CVEIDs {
			cves = append(cves, Cve{
				CveID: cveID,
				Href:  fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID),
			})
		}

		packs := []Package{}
		for _, pack := range update.Packages {
			packs = append(packs, Package{
				Name:            pack.Name,
				Version:         fmt.Sprintf("%s:%s-%s", pack.Epoch, pack.Version, pack.Release),
				Arch:            pack.Arch,
				ModularityLabel: update.ModularityLabel,
			})
		}

		refs := []Reference{}
		bs := []Bugzilla{}
		for _, ref := range update.References {
			refs = append(refs, Reference{
				Source: ref.Type,
				RefID:  ref.ID,
				RefURL: ref.Href,
			})
			if ref.Type == "bugzilla" {
				bs = append(bs, Bugzilla{
					BugzillaID: ref.ID,
					URL:        ref.Href,
					Title:      ref.Title,
				})
			}
		}

		issuedAt := util.ParsedOrDefaultTime("2006-01-02 15:04:05", update.Issued.Date)
		updatedAt := util.ParsedOrDefaultTime("2006-01-02 15:04:05", update.Updated.Date)
		def := Definition{
			DefinitionID: "def-" + update.ID,
			Title:        update.ID,
			Description:  update.Description,
			Advisory: Advisory{
				Severity:        update.Severity,
				Cves:            cves,
				Bugzillas:       bs,
				AffectedCPEList: []Cpe{},
				Issued:          issuedAt,
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
