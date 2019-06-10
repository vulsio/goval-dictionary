package fetcher

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"net/url"
	"path"

	"github.com/inconshreveable/log15"
)

const (
	amazonLinux1MirrorListURI = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	amazonLinux2MirrorListURI = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
)

// RepoMd has repomd data
type RepoMd struct {
	RepoList []Repo `xml:"data"`
}

// Repo has a repo data
type Repo struct {
	Type     string   `xml:"type,attr"`
	Location Location `xml:"location"`
}

// Location has a location of repomd
type Location struct {
	Href string `xml:"href,attr"`
}

// UpdateInfo has a list of ALAS
type UpdateInfo struct {
	ALASList []ALAS `xml:"update"`
}

// ALAS has detailed data of ALAS
type ALAS struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Updated     Updated     `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	References  []Reference `xml:"references>reference" json:"references,omitempty"`
	CVEIDs      []string    `json:"cveiDs,omitempty"`
}

// Updated has updated at
type Updated struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

// Reference has reference informaiton
type Reference struct {
	Href  string `xml:"href,attr" json:"href,omitempty"`
	ID    string `xml:"id,attr" json:"id,omitempty"`
	Title string `xml:"title,attr" json:"title,omitempty"`
	Type  string `xml:"type,attr" json:"type,omitempty"`
}

// Package has affected package information
type Package struct {
	Name     string `xml:"name,attr" json:"name,omitempty"`
	Epoch    string `xml:"epoch,attr" json:"epoch,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Release  string `xml:"release,attr" json:"release,omitempty"`
	Arch     string `xml:"arch,attr" json:"arch,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
}

// FetchUpdateInfoAmazonLinux1 fetches a list of Amazon Linux1 updateinfo
func FetchUpdateInfoAmazonLinux1() (*UpdateInfo, error) {
	return fetchUpdateInfoAmazonLinux(amazonLinux1MirrorListURI)
}

// FetchUpdateInfoAmazonLinux2 fetches a list of Amazon Linux2 updateinfo
func FetchUpdateInfoAmazonLinux2() (*UpdateInfo, error) {
	return fetchUpdateInfoAmazonLinux(amazonLinux2MirrorListURI)
}

func fetchUpdateInfoAmazonLinux(mirrorListURL string) (uinfo *UpdateInfo, err error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: mirrorListURL}})
	if err != nil || len(results) != 1 {
		return nil, fmt.Errorf("Failed to fetch mirror list files. err: %s", err)
	}

	mirrors := []string{}
	for _, r := range results {
		scanner := bufio.NewScanner(bytes.NewReader(r.Body))
		for scanner.Scan() {
			mirrors = append(mirrors, scanner.Text())
		}
	}

	uinfoURLs, err := fetchUpdateInfoURL(mirrors)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch updateInfo URL. err: %s", err)
	}
	for _, url := range uinfoURLs {
		uinfo, err = fetchUpdateInfo(url)
		if err != nil {
			log15.Warn("Failed to fetch updateinfo. continue with other mirror", "err", err)
			continue
		}
		return uinfo, nil
	}
	return nil, fmt.Errorf("Failed to fetch updateinfo")
}

// FetchUpdateInfoURL fetches update info urls for AmazonLinux1 and Amazon Linux2.
func fetchUpdateInfoURL(mirrors []string) (updateInfoURLs []string, err error) {
	reqs := []fetchRequest{}
	for _, mirror := range mirrors {
		u, err := url.Parse(mirror)
		if err != nil {
			return nil, err
		}
		u.Path = path.Join(u.Path, "/repodata/repomd.xml")
		reqs = append(reqs, fetchRequest{
			target:       mirror, // base URL of the mirror site
			url:          u.String(),
			concurrently: true,
		})
	}

	results, err := fetchFeedFiles(reqs)
	if err != nil {
		log15.Warn("Some errors occurred while fetching repomd", "err", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("Failed to fetch repomd.xml. URLs: %s",
			mirrors)
	}

	for _, r := range results {
		var repoMd RepoMd
		if err := xml.NewDecoder(bytes.NewBuffer(r.Body)).Decode(&repoMd); err != nil {
			log15.Warn("Failed to decode repomd. Trying another mirror", "err", err)
			continue
		}

		for _, repo := range repoMd.RepoList {
			if repo.Type == "updateinfo" {
				u, err := url.Parse(r.Target)
				if err != nil {
					return nil, err
				}
				u.Path = path.Join(u.Path, repo.Location.Href)
				updateInfoURLs = append(updateInfoURLs, u.String())
				break
			}
		}
	}
	if len(updateInfoURLs) == 0 {
		return nil, fmt.Errorf("No updateinfo field in the repomd")
	}
	return updateInfoURLs, nil
}

func fetchUpdateInfo(url string) (*UpdateInfo, error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: url}})
	if err != nil || len(results) != 1 {
		return nil, fmt.Errorf("Failed to fetch updateInfo. err: %s", err)
	}
	r, err := gzip.NewReader(bytes.NewBuffer(results[0].Body))
	if err != nil {
		return nil, fmt.Errorf("Failed to decomparess updateInfo. err: %s", err)
	}
	defer r.Close()

	var updateInfo UpdateInfo
	if err := xml.NewDecoder(r).Decode(&updateInfo); err != nil {
		return nil, err
	}
	for i, alas := range updateInfo.ALASList {
		cveIDs := []string{}
		for _, ref := range alas.References {
			if ref.Type == "cve" {
				cveIDs = append(cveIDs, ref.ID)
			}
		}
		updateInfo.ALASList[i].CVEIDs = cveIDs
	}
	return &updateInfo, nil
}
