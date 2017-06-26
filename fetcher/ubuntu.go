package fetcher

import (
	"fmt"

	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
)

func newUbuntuFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml"
	for _, v := range target {
		var name string
		if name = ubuntuName(v); name == "unknown" {
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

func ubuntuName(major string) string {
	switch major {
	case "12":
		return config.Ubuntu12
	case "14":
		return config.Ubuntu14
	case "16":
		return config.Ubuntu16
	default:
		return "unknown"
	}
}

// FetchUbuntuFiles fetch OVAL from Ubuntu
func FetchUbuntuFiles(versions []string) ([]FetchResult, error) {
	reqs := newUbuntuFetchRequests(versions)
	results, err := fetchFeedFileConcurrently(reqs)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}
