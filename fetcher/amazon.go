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

// RepoMd has repomd data
type RepoMd struct {
	RepoList []Repo `xml:"data"`
}

// Repo has a repo data
type Repo struct {
	Type     string   `xml:"type,attr"`
	Location Location `xml:"location"`
}

// Location has a location of repomd
type Location struct {
	Href string `xml:"href,attr"`
}

// UpdateInfo has a list of ALAS
type UpdateInfo struct {
	ALASList []ALAS `xml:"update"`
}

// ALAS has detailed data of ALAS
type ALAS struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Updated     Updated     `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	References  []Reference `xml:"references>reference" json:"references,omitempty"`
	CVEIDs      []string    `json:"cveiDs,omitempty"`
}

// Updated has updated at
type Updated struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

// Reference has reference information
type Reference struct {
	Href  string `xml:"href,attr" json:"href,omitempty"`
	ID    string `xml:"id,attr" json:"id,omitempty"`
	Title string `xml:"title,attr" json:"title,omitempty"`
	Type  string `xml:"type,attr" json:"type,omitempty"`
}

// Package has affected package information
type Package struct {
	Name     string `xml:"name,attr" json:"name,omitempty"`
	Epoch    string `xml:"epoch,attr" json:"epoch,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Release  string `xml:"release,attr" json:"release,omitempty"`
	Arch     string `xml:"arch,attr" json:"arch,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
}

// Root is a struct of releasemd.xml for AL2022
// curl https://al2022-repos-us-west-2-9761ab97.s3.dualstack.us-west-2.amazonaws.com/core/releasemd.xml
type Root struct {
	XMLName  xml.Name `xml:"root"`
	Releases struct {
		Release []struct {
			Version string `xml:"version,attr"`
			Update  []struct {
				Name          string `xml:"name"`
				VersionString string `xml:"version_string"`
				ReleaseNotes  string `xml:"release_notes"`
			} `xml:"update"`
		} `xml:"release"`
	} `xml:"releases"`
}

// FetchUpdateInfoAmazonLinux1 fetches a list of Amazon Linux1 updateinfo
func FetchUpdateInfoAmazonLinux1() (*UpdateInfo, error) {
	return fetchUpdateInfoAmazonLinux(al1MirrorListURI)
}

// FetchUpdateInfoAmazonLinux2 fetches a list of Amazon Linux2 updateinfo
func FetchUpdateInfoAmazonLinux2() (*UpdateInfo, error) {
	return fetchUpdateInfoAmazonLinux(al2MirrorListURI)
}

// FetchUpdateInfoAmazonLinux2022 fetches a list of Amazon Linux2022 updateinfo
func FetchUpdateInfoAmazonLinux2022() (*UpdateInfo, error) {
	uri, err := getAmazonLinux2022MirrorListURI()
	if err != nil {
		return nil, err
	}
	return fetchUpdateInfoAmazonLinux(uri)
}

func getAmazonLinux2022MirrorListURI() (uri string, err error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: al2022ReleasemdURI}})
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

func fetchUpdateInfoAmazonLinux(mirrorListURL string) (uinfo *UpdateInfo, err error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: mirrorListURL}})
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

func fetchUpdateInfo(url string) (*UpdateInfo, error) {
	results, err := fetchFeedFiles([]fetchRequest{{url: url}})
	if err != nil || len(results) != 1 {
		return nil, xerrors.Errorf("Failed to fetch updateInfo. err: %w", err)
	}
	r, err := gzip.NewReader(bytes.NewBuffer(results[0].Body))
	if err != nil {
		return nil, xerrors.Errorf("Failed to decompress updateInfo. err: %w", err)
	}
	defer r.Close()

	var updateInfo UpdateInfo
	if err := xml.NewDecoder(r).Decode(&updateInfo); err != nil {
		return nil, err
	}
	for i, alas := range updateInfo.ALASList {
		cveIDs := []string{}
		for _, ref := range alas.References {
			if ref.Type == "cve" {
				cveIDs = append(cveIDs, ref.ID)
			}
		}
		updateInfo.ALASList[i].CVEIDs = cveIDs
	}
	return &updateInfo, nil
}
