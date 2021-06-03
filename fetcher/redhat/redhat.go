package redhat

import (
	"fmt"

	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/fetcher/util"
)

func newFetchRequests(targets []string) map[string][]util.FetchRequest {
	const tV1 = "https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%s.xml.bz2"
	const tV2 = "https://www.redhat.com/security/data/oval/v2/RHEL%s/rhel-%s.oval.xml.bz2"

	reqs := map[string][]util.FetchRequest{}
	for _, v := range targets {
		urls := []string{}
		switch v[:1] {
		case "5":
			urls = append(urls, fmt.Sprintf(tV1, v))
		case "6", "7":
			urls = append(urls, fmt.Sprintf(tV2, v[:1], v))
			urls = append(urls, fmt.Sprintf(tV2, v[:1], fmt.Sprintf("%s-extras", v[:1])))
		case "8":
			urls = append(urls, fmt.Sprintf(tV2, v[:1], v))
		}

		rs := []util.FetchRequest{}
		for _, u := range urls {
			rs = append(rs, util.FetchRequest{
				Target:       v,
				URL:          u,
				MIMEType:     util.MIMETypeBzip2,
				Concurrently: false,
			})
		}
		reqs[v] = rs
	}

	return reqs
}

// FetchFiles fetch OVAL from RedHat
func FetchFiles(versions []string) (map[string][]util.FetchResult, error) {
	reqsPerVersion := newFetchRequests(versions)
	if len(reqsPerVersion) == 0 {
		return nil, xerrors.New("Failed to build request. err: no versions to fetch")
	}

	resultsPerVersion := map[string][]util.FetchResult{}
	for v, reqs := range reqsPerVersion {
		results, err := util.FetchFeedFiles(reqs)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
		}
		resultsPerVersion[v] = results
	}

	return resultsPerVersion, nil
}

// FetchRepositoryToCPEFile fetch repository-to-cpe.json
func FetchRepositoryToCPEFile() (util.FetchResult, error) {
	req := util.FetchRequest{
		Target:   "repository-to-cpe.json",
		URL:      "https://www.redhat.com/security/data/metrics/repository-to-cpe.json",
		MIMEType: util.MIMETypeJSON,
	}
	result, err := util.FetchFeedFiles([]util.FetchRequest{req})
	if err != nil {
		return util.FetchResult{}, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return util.FetchResult{Target: req.Target, URL: req.URL, Body: result[0].Body}, nil
}
