package redhat

import (
	"fmt"

	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/fetcher/util"
)

func newFetchRequests(target []string) (reqs []util.FetchRequest) {
	const t = "https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%s.xml.bz2"
	for _, v := range target {
		reqs = append(reqs, util.FetchRequest{
			Target:       v,
			URL:          fmt.Sprintf(t, v),
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
