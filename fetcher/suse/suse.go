package suse

import (
	"fmt"

	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/fetcher/util"
)

// https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.42.2.xml
// https://ftp.suse.com/pub/projects/security/oval/opensuse.13.2.xml
// https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.desktop.12.xml"
// https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.12.xml
func newFetchRequests(suseType string, target []string) (reqs []util.FetchRequest) {
	const t = "https://ftp.suse.com/pub/projects/security/oval/%s.%s.xml"
	for _, v := range target {
		reqs = append(reqs, util.FetchRequest{
			Target:       v,
			URL:          fmt.Sprintf(t, suseType, v),
			Concurrently: true,
			MIMEType:     util.MIMETypeXML,
		})
	}
	return
}

// FetchFiles fetch OVAL from RedHat
func FetchFiles(suseType string, versions []string) ([]util.FetchResult, error) {
	reqs := newFetchRequests(suseType, versions)
	if len(reqs) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}
	results, err := util.FetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}
