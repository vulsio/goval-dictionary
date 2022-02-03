package fetcher

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"net/url"
	"path"
	"sort"

	"github.com/inconshreveable/log15"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"
)

// updateinfo for x86_64 also contains information for aarch64
const (
	al1MirrorListURI   = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	al2MirrorListURI   = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
	al2022ReleasemdURI = "https://al2022-repos-us-west-2-9761ab97.s3.dualstack.us-west-2.amazonaws.com/core/releasemd.xml"
)

// FetchUpdateInfoAmazonLinux1 fetches a list of Amazon Linux1 updateinfo
func FetchUpdateInfoAmazonLinux1() (*AmazonUpdates, error) {
	return fetchUpdateInfoAmazonLinux(al1MirrorListURI)
}

// FetchUpdateInfoAmazonLinux2 fetches a list of Amazon Linux2 updateinfo
func FetchUpdateInfoAmazonLinux2() (*AmazonUpdates, error) {
	return fetchUpdateInfoAmazonLinux(al2MirrorListURI)
}

// FetchUpdateInfoAmazonLinux2022 fetches a list of Amazon Linux2022 updateinfo
func FetchUpdateInfoAmazonLinux2022() (*AmazonUpdates, error) {
	uri, err := getAmazonLinux2022MirrorListURI()
	if err != nil {
		return nil, err
	}
	return fetchUpdateInfoAmazonLinux(uri)
}

func getAmazonLinux2022MirrorListURI() (uri string, err error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: al2022ReleasemdURI, mimeType: mimeTypeXML}})
	if err != nil || len(results) != 1 {
		return "", xerrors.Errorf("Failed to fetch releasemd.xml for AL2022. url: %s, err: %w", al2022ReleasemdURI, err)
	}

	var root Root
	// Since the XML charset encoding is defined as `utf8` instead of `utf-8`, the following error will occur if it do not set decoder.CharsetReader.
	// `Failed to fetch updateinfo for Amazon Linux2022. err: xml: encoding "utf8" declared but Decoder.CharsetReader is nil`
	decoder := xml.NewDecoder(bytes.NewReader(results[0].Body))
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&root); err != nil {
		return "", xerrors.Errorf("Failed to decode releasemd.xml for AL2022. err: %w", err)
	}

	versions := []string{}
	for _, release := range root.Releases.Release {
		versions = append(versions, release.Version)
	}
	if len(versions) == 0 {
		return "", xerrors.Errorf("Failed to get the latest version of al2022. url: %s", al2022ReleasemdURI)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(versions)))
	return fmt.Sprintf("https://al2022-repos-us-east-1-9761ab97.s3.dualstack.us-east-1.amazonaws.com/core/mirrors/%s/x86_64/mirror.list", versions[0]), nil
}

func fetchUpdateInfoAmazonLinux(mirrorListURL string) (uinfo *AmazonUpdates, err error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: mirrorListURL, mimeType: mimeTypeXML}})
	if err != nil || len(results) != 1 {
		return nil, xerrors.Errorf("Failed to fetch mirror list files. err: %w", err)
	}

	mirrors := []string{}
	for _, r := range results {
		scanner := bufio.NewScanner(bytes.NewReader(r.Body))
		for scanner.Scan() {
			mirrors = append(mirrors, scanner.Text())
		}
	}

	uinfoURLs, err := fetchUpdateInfoURL(mirrors)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch updateInfo URL. err: %w", err)
	}
	for _, url := range uinfoURLs {
		uinfo, err = fetchUpdateInfo(url)
		if err != nil {
			log15.Warn("Failed to fetch updateinfo. continue with other mirror", "err", err)
			continue
		}
		return uinfo, nil
	}
	return nil, fmt.Errorf("Failed to fetch updateinfo")
}

// FetchUpdateInfoURL fetches update info urls for AmazonLinux1 ,Amazon Linux2 and Amazon Linux2022.
func fetchUpdateInfoURL(mirrors []string) (updateInfoURLs []string, err error) {
	reqs := []fetchRequest{}
	for _, mirror := range mirrors {
		u, err := url.Parse(mirror)
		if err != nil {
			return nil, err
		}
		u.Path = path.Join(u.Path, "/repodata/repomd.xml")
		reqs = append(reqs, fetchRequest{
			target:       mirror, // base URL of the mirror site
			url:          u.String(),
			concurrently: true,
			mimeType:     mimeTypeXML,
		})
	}

	results, err := fetchFeedFiles(reqs)
	if err != nil {
		log15.Warn("Some errors occurred while fetching repomd", "err", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("Failed to fetch repomd.xml. URLs: %s",
			mirrors)
	}

	for _, r := range results {
		var repoMd RepoMd
		if err := xml.NewDecoder(bytes.NewBuffer(r.Body)).Decode(&repoMd); err != nil {
			log15.Warn("Failed to decode repomd. Trying another mirror", "err", err)
			continue
		}

		for _, repo := range repoMd.RepoList {
			if repo.Type == "updateinfo" {
				u, err := url.Parse(r.Target)
				if err != nil {
					return nil, err
				}
				u.Path = path.Join(u.Path, repo.Location.Href)
				updateInfoURLs = append(updateInfoURLs, u.String())
				break
			}
		}
	}
	if len(updateInfoURLs) == 0 {
		return nil, fmt.Errorf("No updateinfo field in the repomd")
	}
	return updateInfoURLs, nil
}

func fetchUpdateInfo(url string) (*AmazonUpdates, error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: url, mimeType: mimeTypeXML}})
	if err != nil || len(results) != 1 {
		return nil, xerrors.Errorf("Failed to fetch updateInfo. err: %w", err)
	}
	r, err := gzip.NewReader(bytes.NewBuffer(results[0].Body))
	if err != nil {
		return nil, xerrors.Errorf("Failed to decompress updateInfo. err: %w", err)
	}
	defer r.Close()

	var updateInfo AmazonUpdates
	if err := xml.NewDecoder(r).Decode(&updateInfo); err != nil {
		return nil, err
	}
	for i, alas := range updateInfo.UpdateList {
		cveIDs := []string{}
		for _, ref := range alas.References {
			if ref.Type == "cve" {
				cveIDs = append(cveIDs, ref.ID)
			}
		}
		updateInfo.UpdateList[i].CVEIDs = cveIDs
	}
	return &updateInfo, nil
}
