package fetcher

import (
	"fmt"

	"golang.org/x/xerrors"
)

// https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.42.2.xml
// https://ftp.suse.com/pub/projects/security/oval/opensuse.13.2.xml
// https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.desktop.12.xml"
// https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.12.xml
// https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.7.xml
func newSUSEFetchRequests(suseType string, target []string) (reqs []fetchRequest) {
	const t = "https://ftp.suse.com/pub/projects/security/oval/%s.%s.xml"
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(t, suseType, v),
			concurrently: true,
		})
	}
	return
}

// FetchSUSEFiles fetch OVAL from RedHat
func FetchSUSEFiles(suseType string, versions []string) ([]FetchResult, error) {
	reqs := newSUSEFetchRequests(suseType, versions)
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
