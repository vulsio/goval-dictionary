package ubuntu

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/fetcher/util"
)

func newFetchRequests(target []string) (reqs []util.FetchRequest) {
	for _, v := range target {
		switch url := getOVALURL(v); url {
		case "unknown":
			log15.Warn("Skip unknown ubuntu.", "version", v)
		case "unsupported":
			log15.Warn("Skip unsupported ubuntu version.", "version", v)
			log15.Warn("See https://wiki.ubuntu.com/Releases for supported versions")
		default:
			reqs = append(reqs, util.FetchRequest{
				Target:       v,
				URL:          url,
				Concurrently: true,
				MIMEType:     util.MIMETypeBzip2,
			})
		}
	}
	return
}

func getOVALURL(major string) string {
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

// FetchFiles fetch OVAL from Ubuntu
func FetchFiles(versions []string) ([]util.FetchResult, error) {
	reqs := newFetchRequests(versions)
	if len(reqs) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}
	results, err := util.FetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}
