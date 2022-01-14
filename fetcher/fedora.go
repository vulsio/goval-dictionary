package fetcher

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
)

func newFedoraFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Everything/x86_64/repodata/repomd.xml"
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(t, v),
			bzip2:        false,
			xz:           false,
			concurrently: false,
		})
	}
	return
}

// FetchFedora fetch OVAL from Fedora
func FetchUpdateInfosFedora(versions []string) (map[string]FedoraUpdates, error) {
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
					url:          u.String(),
					target:       r.Target,
					bzip2:        false,
					xz:           true,
					concurrently: false,
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

func parseFetchResultsFedora(results []FetchResult) (map[string]FedoraUpdates, error) {
	updateInfos := make(map[string]FedoraUpdates, len(results))
	for _, r := range results {
		var updateInfo FedoraUpdates
		if err := xml.NewDecoder(bytes.NewReader(r.Body)).Decode(&updateInfo); err != nil {
			return nil, err
		}
		var securityUpdate []FedoraUpdateInfo
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
