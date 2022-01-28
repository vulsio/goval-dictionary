package fetcher

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/goval-dictionary/config"
	"golang.org/x/xerrors"
)

func newUbuntuFetchRequests(target []string) (reqs []fetchRequest) {
	for _, v := range target {
		switch url := getUbuntuOVALURL(v); url {
		case "unknown":
			log15.Warn("Skip unknown ubuntu.", "version", v)
		case "unsupported":
			log15.Warn("Skip unsupported ubuntu version.", "version", v)
			log15.Warn("See https://wiki.ubuntu.com/Releases for supported versions")
		default:
			reqs = append(reqs, fetchRequest{
				target:       v,
				url:          url,
				concurrently: true,
				bzip2:        true,
			})
		}
	}
	return
}

func getUbuntuOVALURL(major string) string {
	const main = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	const sub = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml.bz2"

	switch major {
	case "12":
		return "unsupported"
	case "14":
		return fmt.Sprintf(main, config.Ubuntu14)
	case "16":
		return fmt.Sprintf(main, config.Ubuntu16)
	case "17":
		return "unsupported"
	case "18":
		return fmt.Sprintf(main, config.Ubuntu18)
	case "19":
		return fmt.Sprintf(sub, config.Ubuntu19)
	case "20":
		return fmt.Sprintf(main, config.Ubuntu20)
	case "21":
		return fmt.Sprintf(main, config.Ubuntu21)
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
			xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}
