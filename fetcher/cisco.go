package fetcher

import (
	"fmt"
)

func newCiscoFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://oval.cisecurity.org/repository/download/5.11.2/vulnerability/cisco_%s.xml"
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

// FetchCiscoFiles fetch OVAL from Cisco
func FetchCiscoFiles(versions []string) ([]FetchResult, error) {
	reqs := newCiscoFetchRequests(versions)
	if len(reqs) == 0 {
		return nil,
			fmt.Errorf("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}
