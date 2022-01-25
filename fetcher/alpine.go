package fetcher

import (
	"fmt"

	"golang.org/x/xerrors"
)

const community = "https://secdb.alpinelinux.org/v%s/community.yaml"
const main = "https://secdb.alpinelinux.org/v%s/main.yaml"

func newAlpineFetchRequests(target []string) (reqs []fetchRequest) {
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target:   v,
			url:      fmt.Sprintf(main, v),
			mimeType: mimeTypeYml,
		})

		if v != "3.2" {
			reqs = append(reqs, fetchRequest{
				target:   v,
				url:      fmt.Sprintf(community, v),
				mimeType: mimeTypeYml,
			})
		}
	}
	return
}

// FetchAlpineFiles fetch from alpine secdb
// https://secdb.alpinelinux.org/
func FetchAlpineFiles(versions []string) ([]FetchResult, error) {
	reqs := newAlpineFetchRequests(versions)
	if len(reqs) == 0 {
		return nil,
			fmt.Errorf("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil,
			xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}
