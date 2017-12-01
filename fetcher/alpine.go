package fetcher

import (
	"fmt"
)

const community = "https://git.alpinelinux.org/cgit/alpine-secdb/plain/v%s/community.yaml"
const main = "https://git.alpinelinux.org/cgit/alpine-secdb/plain/v%s/main.yaml"

func newAlpineFetchRequests(target []string) (reqs []fetchRequest) {
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target: v,
			url:    fmt.Sprintf(community, v),
		}, fetchRequest{
			target: v,
			url:    fmt.Sprintf(main, v),
		})
	}
	return
}

// FetchAlpineFiles fetch from alpine secdb
// https://git.alpinelinux.org/cgit/alpine-secdb/tree/
func FetchAlpineFiles(versions []string) ([]FetchResult, error) {
	reqs := newAlpineFetchRequests(versions)
	results, err := fetchFeedFileConcurrently(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}
