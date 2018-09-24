package fetcher

import (
	"fmt"
)

func newOracleFetchRequests() (reqs []fetchRequest) {
	const t = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"
	reqs = append(reqs, fetchRequest{
		url:   t,
		bzip2: true,
	})
	return
}

// FetchOracleFiles fetch OVAL from Oracle
func FetchOracleFiles() ([]FetchResult, error) {
	reqs := newOracleFetchRequests()
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
