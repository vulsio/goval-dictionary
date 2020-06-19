package fetcher

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/kotakanbe/goval-dictionary/config"
)

func newUbuntuFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	for _, v := range target {
		var name string
		if name = ubuntuName(v); name == "unknown" {
			log15.Warn("Skip unknown ubuntu.", "version", v)
			continue
		} else if name = ubuntuName(v); name == "unsupported" {
			log15.Warn("Skip unsupported ubuntu version.", "version", v)
			log15.Warn("See https://wiki.ubuntu.com/Releases for supported versions")
			continue
		}
		reqs = append(reqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(t, name),
			concurrently: true,
			bzip2:        true,
		})
	}
	return
}

func ubuntuName(major string) string {
	switch major {
	case "12":
		return "unsupported"
	case "14":
		return config.Ubuntu14
	case "16":
		return config.Ubuntu16
	case "17":
		return "unsupported"
	case "18":
		return config.Ubuntu18
	case "19":
		return config.Ubuntu19
	case "20":
		return config.Ubuntu20
	default:
		return "unknown"
	}
}

// FetchUbuntuFiles fetch OVAL from Ubuntu
func FetchUbuntuFiles(versions []string) ([]FetchResult, error) {
	reqs := newUbuntuFetchRequests(versions)
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
