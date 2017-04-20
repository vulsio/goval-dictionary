package fetcher

import (
	"fmt"
)

func newRedHatFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://www.redhat.com/security/data/oval/Red_Hat_Enterprise_Linux_%s.xml"
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target: v,
			url:    fmt.Sprintf(t, v),
		})
	}
	return
}

// FetchRedHatFiles fetch OVAL from RedHat
func FetchRedHatFiles(versions []string) ([]FetchResult, error) {
	reqs := newRedHatFetchRequests(versions)
	results, err := fetchFeedFileConcurrently(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}
