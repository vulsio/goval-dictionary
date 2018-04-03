package models

import (
	"strings"
	"time"

	"github.com/inconshreveable/log15"
)

// AmazonRSS is a struct of alpine secdb
type AmazonRSS struct {
	Items []item `xml:"channel>item"`
}

type item struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
	Link        string `xml:"link"`
}

func descToCveIDs(description string) (cveIDs []string) {
	ss := strings.Split(description, ",")
	for _, s := range ss {
		cveIDs = append(cveIDs, strings.TrimSpace(s))
	}
	return
}

func parseTitle(title string) (alas, severity string, packNames []string) {
	ss := strings.Fields(title)
	if len(ss) < 3 {
		log15.Info("Unknown format", "title", title)
	}
	alas = ss[0]
	severity = strings.TrimRight(strings.TrimLeft(ss[1], "("), ":)")
	for _, name := range ss[2:] {
		s := strings.TrimSpace(strings.TrimRight(name, ","))
		packNames = append(packNames, s)
	}
	return
}

// ConvertAmazonToModel Convert OVAL to models
func ConvertAmazonToModel(data *AmazonRSS) (defs []Definition) {
	for _, item := range data.Items {

		cves := []Cve{}
		cveIDs := descToCveIDs(item.Description)
		for _, id := range cveIDs {
			cves = append(cves, Cve{CveID: id})
		}

		packs := []Package{}
		alas, severity, names := parseTitle(item.Title)
		for _, n := range names {
			packs = append(packs, Package{
				Name: n,
			})
		}

		issued, _ := time.Parse(time.RFC1123, item.PubDate)

		refs := []Reference{}
		for _, id := range cveIDs {
			refs = append(refs, Reference{
				Source: "CVE",
				RefID:  id,
				RefURL: item.Link,
			})
		}

		defs = append(defs, Definition{
			DefinitionID:  "def-" + alas,
			Title:         alas,
			AffectedPacks: packs,
			Advisory: Advisory{
				Cves:     cves,
				Severity: severity,
				Issued:   issued,
			},
			References: refs,
		})
	}
	return
}
