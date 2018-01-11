package models

import (
	"strings"
	"time"

	"github.com/kotakanbe/goval-dictionary/log"
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
		log.Infof("Unknown format : %s", title)
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

		Cves := []Cve{}
		cveIDs := descToCveIDs(item.Description)
		for _, id := range cveIDs {
			Cves = append(Cves, Cve{CveID: id})
		}

		packs := []Package{}
		_, severity, names := parseTitle(item.Title)
		alas, severity, names := parseTitle(item.Title)
		for _, n := range names {
			packs = append(packs, Package{
				Name: n,
			})
		}

		issued, _ := time.Parse(time.RFC1123, item.PubDate)

		defs = append(defs, Definition{
			Title:         alas,
			AffectedPacks: packs,
			Advisory: Advisory{
				Cves:     Cves,
				Severity: severity,
				Issued:   issued,
			},
			References: []Reference{
				{RefURL: item.Link},
			},
		})
	}
	return
}
