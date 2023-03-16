package redhat

import (
	"fmt"
	"strconv"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/fetcher/util"
)

func newFetchRequests(target []string) (reqs []util.FetchRequest) {
	for _, v := range target {
		n, err := strconv.Atoi(v)
		if err != nil {
			log15.Warn("Skip unknown redhat.", "version", v)
			continue
		}

		if n < 5 {
			log15.Warn("Skip redhat because no vulnerability information provided.", "version", v)
			continue
		}
		reqs = append(reqs, util.FetchRequest{
			Target:       v,
			URL:          fmt.Sprintf("https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%s.xml.bz2", v),
			MIMEType:     util.MIMETypeBzip2,
			Concurrently: false,
		})
	}
	return
}

// FetchFiles fetch OVAL from RedHat
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
