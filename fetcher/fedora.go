package fetcher

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/ulikunitz/xz"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
)

// FedoraUpdateInfo has a list of Update Info
type FedoraUpdateInfo struct {
	UpdateList []FedoraUpdate `xml:"update"`
}

// FedoraUpdate has detailed data of Update Info
type FedoraUpdate struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Issued      Issued      `xml:"issued" json:"issued,omitempty"`
	Updated     Updated     `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	References  []Reference `xml:"references>reference" json:"references,omitempty"`
	CVEIDs      []string    `json:"cveiDs,omitempty"`
	Type        string      `xml:"type,attr" json:"type,omitempty"`
}

// Issued has issued at
type Issued struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

func newFedoraFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Everything/x86_64/repodata/repomd.xml"
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(t, v),
			bzip2:        false,
			concurrently: false,
		})
	}
	return
}

// FetchFedora fetch OVAL from Fedora
func FetchUpdateInfosFedora(versions []string) (map[string]FedoraUpdateInfo, error) {
	feeds, err := fetchFeedFilesFedora(versions)
	if err != nil {
		return nil, err
	}

	updates, err := fetchUpdateInfosFedora(feeds)
	if err != nil {
		return nil, err
	}

	results, err := parseFetchResultsFedora(updates)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func fetchFeedFilesFedora(versions []string) ([]FetchResult, error) {
	reqs := newFedoraFetchRequests(versions)
	if len(reqs) == 0 {
		return nil, fmt.Errorf("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

func fetchUpdateInfosFedora(results []FetchResult) ([]FetchResult, error) {
	// extract updateinfo
	var updateInfoReqs []fetchRequest
	for _, r := range results {
		var repoMd RepoMd
		if err := xml.NewDecoder(bytes.NewBuffer(r.Body)).Decode(&repoMd); err != nil {
			log15.Warn(fmt.Sprintf("Failed to decode repomd. Skip to fetch version %s", r.Target), "err", err)
			continue
		}

		for _, repo := range repoMd.RepoList {
			if repo.Type == "updateinfo" {
				u, err := url.Parse(r.URL)
				if err != nil {
					return nil, err
				}
				u.Path = strings.Replace(u.Path, "repodata/repomd.xml", repo.Location.Href, 1)
				req := fetchRequest{
					url:    u.String(),
					target: r.Target,
				}
				updateInfoReqs = append(updateInfoReqs, req)
				break
			}
		}
	}

	if len(updateInfoReqs) == 0 {
		return nil, fmt.Errorf("No updateinfo field in the repomd")
	}

	results, err := fetchFeedFiles(updateInfoReqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

func parseFetchResultsFedora(results []FetchResult) (map[string]FedoraUpdateInfo, error) {
	updateInfos := make(map[string]FedoraUpdateInfo, len(results))
	for _, r := range results {
		reader, err := xz.NewReader(bytes.NewBuffer(r.Body))
		if err != nil {
			return nil, xerrors.Errorf("Failed to decompress updateInfo. err: %w", err)
		}
		var updateInfo FedoraUpdateInfo
		if err := xml.NewDecoder(reader).Decode(&updateInfo); err != nil {
			return nil, err
		}
		var securityUpdate []FedoraUpdate
		for _, update := range updateInfo.UpdateList {
			if update.Type == "security" {
				cveIDs := []string{}
				for _, ref := range update.References {
					id := util.CveIDPattern.FindString(ref.Title)
					if id != "" {
						cveIDs = append(cveIDs, id)
					}
				}
				if len(cveIDs) != 0 {
					update.CVEIDs = cveIDs
					securityUpdate = append(securityUpdate, update)
				}
			}
		}
		updateInfo.UpdateList = securityUpdate
		updateInfos[r.Target] = updateInfo
	}
	return updateInfos, nil
}
