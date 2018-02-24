package fetcher

import (
	"fmt"
	"strings"

	"github.com/kotakanbe/goval-dictionary/config"
)

// https://www.debian.org/security/oval/
func newDebianFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://www.debian.org/security/oval/oval-definitions-%s.xml"
	for _, v := range target {
		name := debianName(v)
		reqs = append(reqs, fetchRequest{
			target: v,
			url:    fmt.Sprintf(t, name),
		})
	}
	return
}

func debianName(major string) string {
	switch major {
	case "7":
		return config.Debian7
	case "8":
		return config.Debian8
	case "9":
		return config.Debian9
	case "10":
		return config.Debian10
	case "11":
		return config.Debian11
	default:
		return strings.ToLower(major)
	}
}

// FetchDebianFiles fetch OVAL from RedHat
func FetchDebianFiles(versions []string) ([]FetchResult, error) {
	reqs := newDebianFetchRequests(versions)
	if len(reqs) == 0 {
		return nil,
			fmt.Errorf("There are no versions to fetch")
	}
	results, err := fetchFeedFileConcurrently(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}
