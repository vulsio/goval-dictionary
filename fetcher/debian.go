package fetcher

import (
	"fmt"
	"strconv"
)

// FetchDebianFiles fetch OVAL from RedHat
func FetchDebianFiles(years []int) ([]FetchResult, error) {
	syears := []string{}
	for _, y := range years {
		syears = append(syears, strconv.Itoa(y))
	}
	reqs := newDebianFetchRequests(syears)
	results, err := fetchFeedFileConcurrently(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}

func newDebianFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://www.debian.org/security/oval/oval-definitions-%s.xml"
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target: v,
			url:    fmt.Sprintf(t, v),
		})
	}
	return
}
