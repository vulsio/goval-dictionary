package amazon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"

	"github.com/inconshreveable/log15"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/fetcher/util"
	models "github.com/vulsio/goval-dictionary/models/amazon"
)

// updateinfo for x86_64 also contains information for aarch64
const (
	al1MirrorListURI            = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	al2CoreMirrorListURI        = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
	al2ExtraCatalogURI          = "http://amazonlinux.default.amazonaws.com/2/extras-catalog.json"
	al2ExtraMirrorListURIFormat = "https://cdn.amazonlinux.com/2/extras/%s/latest/x86_64/mirror.list"
	al2022ReleasemdURI          = "https://al2022-repos-us-west-2-9761ab97.s3.dualstack.us-west-2.amazonaws.com/core/releasemd.xml"
	al2023ReleasemdURI          = "https://cdn.amazonlinux.com/al2023/core/releasemd.xml"
)

var errNoUpdateInfo = xerrors.New("No updateinfo field in the repomd")

// FetchUpdateInfoAmazonLinux1 fetches a list of Amazon Linux1 updateinfo
func FetchUpdateInfoAmazonLinux1() (*models.Updates, error) {
	return fetchUpdateInfoAmazonLinux(al1MirrorListURI)
}

// FetchUpdateInfoAmazonLinux2 fetches a list of Amazon Linux2 updateinfo
func FetchUpdateInfoAmazonLinux2() (*models.Updates, error) {
	updates, err := fetchUpdateInfoAmazonLinux(al2CoreMirrorListURI)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch Amazon Linux 2 core updateinfo. err: %w", err)
	}
	for i := range updates.UpdateList {
		updates.UpdateList[i].Repository = "amzn2-core"
	}

	rs, err := util.FetchFeedFiles([]util.FetchRequest{{URL: al2ExtraCatalogURI, MIMEType: util.MIMETypeJSON}})
	if err != nil || len(rs) != 1 {
		return nil, xerrors.Errorf("Failed to fetch extras-catalog.json for Amazon Linux 2. url: %s, err: %w", al2ExtraCatalogURI, err)
	}

	var catalog extrasCatalog
	if err := json.Unmarshal(rs[0].Body, &catalog); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal extras-catalog.json for Amazon Linux 2. err: %w", err)
	}

	for _, t := range catalog.Topics {
		us, err := fetchUpdateInfoAmazonLinux(fmt.Sprintf(al2ExtraMirrorListURIFormat, t.N))
		if err != nil {
			if errors.Is(err, errNoUpdateInfo) {
				continue
			}
			return nil, xerrors.Errorf("Failed to fetch Amazon Linux 2 %s updateinfo. err: %w", t.N, err)
		}
		for _, u := range us.UpdateList {
			u.Repository = fmt.Sprintf("amzn2extra-%s", t.N)
			updates.UpdateList = append(updates.UpdateList, u)
		}
	}

	return updates, nil
}

// FetchUpdateInfoAmazonLinux2022 fetches a list of Amazon Linux2022 updateinfo
func FetchUpdateInfoAmazonLinux2022() (*models.Updates, error) {
	uri, err := getAmazonLinux2022MirrorListURI()
	if err != nil {
		return nil, err
	}
	return fetchUpdateInfoAmazonLinux(uri)
}

func getAmazonLinux2022MirrorListURI() (uri string, err error) {
	results, err := util.FetchFeedFiles([]util.FetchRequest{{URL: al2022ReleasemdURI, MIMEType: util.MIMETypeXML}})
	if err != nil || len(results) != 1 {
		return "", xerrors.Errorf("Failed to fetch releasemd.xml for AL2022. url: %s, err: %w", al2022ReleasemdURI, err)
	}

	var root root
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

// FetchUpdateInfoAmazonLinux2023 fetches a list of Amazon Linux2023 updateinfo
func FetchUpdateInfoAmazonLinux2023() (*models.Updates, error) {
	uri, err := getAmazonLinux2023MirrorListURI()
	if err != nil {
		return nil, err
	}
	return fetchUpdateInfoAmazonLinux(uri)
}

func getAmazonLinux2023MirrorListURI() (uri string, err error) {
	results, err := util.FetchFeedFiles([]util.FetchRequest{{URL: al2023ReleasemdURI, MIMEType: util.MIMETypeXML}})
	if err != nil || len(results) != 1 {
		return "", xerrors.Errorf("Failed to fetch releasemd.xml for AL2023. url: %s, err: %w", al2023ReleasemdURI, err)
	}

	var root root
	// Since the XML charset encoding is defined as `utf8` instead of `utf-8`, the following error will occur if it do not set decoder.CharsetReader.
	// `Failed to fetch updateinfo for Amazon Linux2023. err: xml: encoding "utf8" declared but Decoder.CharsetReader is nil`
	decoder := xml.NewDecoder(bytes.NewReader(results[0].Body))
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&root); err != nil {
		return "", xerrors.Errorf("Failed to decode releasemd.xml for AL2023. err: %w", err)
	}

	versions := []string{}
	for _, release := range root.Releases.Release {
		versions = append(versions, release.Version)
	}
	if len(versions) == 0 {
		return "", xerrors.Errorf("Failed to get the latest version of al2023. url: %s", al2023ReleasemdURI)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(versions)))
	return fmt.Sprintf("https://cdn.amazonlinux.com/al2023/core/mirrors/%s/x86_64/mirror.list", versions[0]), nil
}

func fetchUpdateInfoAmazonLinux(mirrorListURL string) (uinfo *models.Updates, err error) {
	results, err := util.FetchFeedFiles([]util.FetchRequest{{URL: mirrorListURL, MIMEType: util.MIMETypeXML}})
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
	return nil, xerrors.New("Failed to fetch updateinfo")
}

// FetchUpdateInfoURL fetches update info urls for AmazonLinux1 ,Amazon Linux2 and Amazon Linux2022.
func fetchUpdateInfoURL(mirrors []string) (updateInfoURLs []string, err error) {
	reqs := []util.FetchRequest{}
	for _, mirror := range mirrors {
		u, err := url.Parse(mirror)
		if err != nil {
			return nil, err
		}
		u.Path = path.Join(u.Path, "/repodata/repomd.xml")
		reqs = append(reqs, util.FetchRequest{
			Target:       mirror, // base URL of the mirror site
			URL:          u.String(),
			Concurrently: true,
			MIMEType:     util.MIMETypeXML,
		})
	}

	results, err := util.FetchFeedFiles(reqs)
	if err != nil {
		log15.Warn("Some errors occurred while fetching repomd", "err", err)
	}
	if len(results) == 0 {
		return nil, xerrors.Errorf("Failed to fetch repomd.xml. URLs: %s", mirrors)
	}

	for _, r := range results {
		var repoMd repoMd
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
		return nil, errNoUpdateInfo
	}
	return updateInfoURLs, nil
}

func fetchUpdateInfo(url string) (*models.Updates, error) {
	results, err := util.FetchFeedFiles([]util.FetchRequest{{URL: url, MIMEType: util.MIMETypeXML}})
	if err != nil || len(results) != 1 {
		return nil, xerrors.Errorf("Failed to fetch updateInfo. err: %w", err)
	}
	r, err := gzip.NewReader(bytes.NewBuffer(results[0].Body))
	if err != nil {
		return nil, xerrors.Errorf("Failed to decompress updateInfo. err: %w", err)
	}
	defer r.Close()

	var updateInfo models.Updates
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
