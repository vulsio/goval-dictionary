package redhat

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/inconshreveable/log15"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/fetcher/util"
)

// FetchFiles fetch OVAL from RedHat
func FetchFiles(versions []string) (map[string][]util.FetchResult, error) {
	results := map[string][]util.FetchResult{}
	vs := make([]string, 0, len(versions))
	for _, v := range versions {
		n, err := strconv.Atoi(v)
		if err != nil {
			log15.Warn("Skip unknown redhat.", "version", v)
			continue
		}

		if n < 5 {
			log15.Warn("Skip redhat because no vulnerability information provided.", "version", v)
			continue
		}

		vs = append(vs, v)
	}
	if len(vs) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}

	log15.Info("Fetching... ", "URL", "https://access.redhat.com/security/data/archive/oval_v1_20230706.tar.gz")
	resp, err := http.Get("https://access.redhat.com/security/data/archive/oval_v1_20230706.tar.gz")
	if err != nil {
		return nil, xerrors.Errorf("Failed to get oval v1. err: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("Failed to get oval v1. err: bad status %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("Failed to create gzip reader. err: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("Failed to next tar reader. err: %w", err)
		}

		v := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "com.redhat.rhsa-RHEL"), ".xml")
		if slices.Contains(vs, v) {
			bs, err := io.ReadAll(tr)
			if err != nil {
				return nil, xerrors.Errorf("Failed to read all com.redhat.rhsa-RHEL%s.xml. err: %w", v, err)
			}
			results[v] = append(results[v], util.FetchResult{
				Target: v,
				URL:    fmt.Sprintf("https://access.redhat.com/security/data/archive/oval_v1_20230706.tar.gz/com.redhat.rhsa-RHEL%s.xml", v),
				Body:   bs,
			})
		}
	}

	reqs := make([]util.FetchRequest, 0, len(vs))
	for _, v := range vs {
		if v != "5" {
			reqs = append(reqs, util.FetchRequest{
				Target:   v,
				URL:      fmt.Sprintf("https://access.redhat.com/security/data/oval/v2/RHEL%s/rhel-%s.oval.xml.bz2", v, v),
				MIMEType: util.MIMETypeBzip2,
			})
		}
	}
	if len(reqs) > 0 {
		rs, err := util.FetchFeedFiles(reqs)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
		}
		for _, r := range rs {
			results[r.Target] = append(results[r.Target], r)
		}
	}

	if len(results) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}
	return results, nil
}
