package fetcher

import (
	"fmt"

	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
)

// https://www.debian.org/security/oval/
func newDebianFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://www.debian.org/security/oval/oval-definitions-%s.xml"
	for _, v := range target {
		var name string
		if name = debianName(v); name == "unknown" {
			log.Warnf("Skip unkown ubuntu version : %s.", v)
			continue
		}
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
	default:
		return "unknown"
	}
}

// FetchDebianFiles fetch OVAL from RedHat
func FetchDebianFiles(versions []string) ([]FetchResult, error) {
	reqs := newDebianFetchRequests(versions)
	results, err := fetchFeedFileConcurrently(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}
