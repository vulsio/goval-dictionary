package fetcher

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

const (
	archX8664   = "x86_64"
	archAarch64 = "aarch64"

	fedoraUpdateURL = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Everything/%s/repodata/repomd.xml"
	fedoraModuleURL = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Modular/%s/repodata/repomd.xml"
	bugZillaURL     = "https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=%s"
	kojiPkgURL      = "https://kojipkgs.fedoraproject.org/packages/%s/%s/%s/files/module/modulemd.%s.txt"
)

// FetchUpdateInfosFedora fetch OVAL from Fedora
func FetchUpdateInfosFedora(versions []string) (FedoraUpdatesPerVersion, error) {
	// map[osVer][updateInfoID]FedoraUpdateInfo
	uinfos := make(map[string]map[string]FedoraUpdateInfo, len(versions))
	for _, arch := range []string{archX8664, archAarch64} {
		reqs, moduleReqs := newFedoraFetchRequests(versions, arch)
		results, err := fetchEverythingFedora(reqs)
		if err != nil {
			return nil, xerrors.Errorf("fetchEverythingFedora. err: %w", err)
		}

		moduleResults, err := fetchModulesFedora(moduleReqs, arch)
		if err != nil {
			return nil, xerrors.Errorf("fetchModulesFedora. err: %w", err)
		}
		results.merge(&moduleResults)

		for osVer, result := range results {
			if _, ok := uinfos[osVer]; !ok {
				uinfos[osVer] = make(map[string]FedoraUpdateInfo, len(result.UpdateList))
			}
			for _, uinfo := range result.UpdateList {
				if tmp, ok := uinfos[osVer][uinfo.ID]; ok {
					uinfo.Packages = append(uinfo.Packages, tmp.Packages...)
				}
				uinfos[osVer][uinfo.ID] = uinfo
			}
		}
	}

	results := map[string]*FedoraUpdates{}
	for osver, uinfoIDs := range uinfos {
		uinfos := &FedoraUpdates{}
		for _, uinfo := range uinfoIDs {
			uinfos.UpdateList = append(uinfos.UpdateList, uinfo)
		}
		results[osver] = uinfos
	}

	for version, v := range results {
		log15.Info(fmt.Sprintf("%d Advisories for Fedora %s Fetched", len(v.UpdateList), version))
	}

	return results, nil
}

func newFedoraFetchRequests(target []string, arch string) (reqs []fetchRequest, moduleReqs []fetchRequest) {
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(fedoraUpdateURL, v, arch),
			mimeType:     mimeTypeXML,
			concurrently: true,
		})
		moduleReqs = append(moduleReqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(fedoraModuleURL, v, arch),
			mimeType:     mimeTypeXML,
			concurrently: true,
		})
	}
	return
}

func fetchEverythingFedora(reqs []fetchRequest) (FedoraUpdatesPerVersion, error) {
	log15.Info("start fetch data from repomd.xml of non-modular package")
	feeds, err := fetchFeedFilesFedora(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch feed file, err: %w", err)
	}

	updates, err := fetchUpdateInfosFedora(feeds)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch updateinfo, err: %w", err)
	}

	results, err := parseFetchResultsFedora(updates)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse fetch results, err: %w", err)
	}

	return results, nil
}

func fetchModulesFedora(reqs []fetchRequest, arch string) (FedoraUpdatesPerVersion, error) {
	log15.Info("start fetch data from repomd.xml of modular")
	feeds, err := fetchModuleFeedFilesFedora(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch feed file, err: %w", err)
	}

	updates, err := fetchUpdateInfosFedora(feeds)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch updateinfo, err: %w", err)
	}

	moduleYaml, err := fetchModulesYamlFedora(feeds)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch module info, err: %w", err)
	}

	results, err := parseFetchResultsFedora(updates)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse fetch results, err: %w", err)
	}

	for version, result := range results {
		for i, update := range result.UpdateList {
			yml, ok := moduleYaml[version][update.Title]
			if !ok {
				yml, err = fetchModuleInfoFromKojiPkgs(arch, update.Title)
				if err != nil {
					return nil, xerrors.Errorf("Failed to fetch module info from kojipkgs.fedoraproject.org, err: %w", err)
				}
			}
			var pkgs []Package
			for _, rpm := range yml.Data.Artifacts.Rpms {
				pkg, err := rpm.NewPackageFromRpm()
				if err != nil {
					return nil, xerrors.Errorf("Failed to build package info from rpm name, err: %w", err)
				}
				pkgs = append(pkgs, pkg)
			}
			results[version].UpdateList[i].Packages = pkgs
			results[version].UpdateList[i].ModularityLabel = yml.ConvertToModularityLabel()
		}
	}
	return results, nil
}

func fetchFeedFilesFedora(reqs []fetchRequest) ([]FetchResult, error) {
	if len(reqs) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

func fetchUpdateInfosFedora(results []FetchResult) ([]FetchResult, error) {
	log15.Info("start fetch updateinfo in repomd.xml")
	updateInfoReqs, err := extractInfoFromRepoMd(results, "updateinfo", mimeTypeXz)
	if err != nil {
		return nil, xerrors.Errorf("Failed to extract updateinfo from xml, err: %w", err)
	}

	if len(updateInfoReqs) == 0 {
		return nil, xerrors.New("No updateinfo field in the repomd")
	}

	results, err = fetchFeedFiles(updateInfoReqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

// variousFlawsPattern is regexp to detect title that omit the part of CVE-IDs by finding both `...` and `various flaws`
var variousFlawsPattern = regexp.MustCompile(`.*\.\.\..*various flaws.*`)

func parseFetchResultsFedora(results []FetchResult) (FedoraUpdatesPerVersion, error) {
	updateInfos := make(FedoraUpdatesPerVersion, len(results))
	for _, r := range results {
		var updateInfo FedoraUpdates
		if err := xml.NewDecoder(bytes.NewReader(r.Body)).Decode(&updateInfo); err != nil {
			return nil, xerrors.Errorf("Failed to decode XML, err: %w", err)
		}
		var securityUpdate []FedoraUpdateInfo
		for _, update := range updateInfo.UpdateList {
			if update.Type != "security" {
				continue
			}
			cveIDs := []string{}
			for _, ref := range update.References {
				var ids []string
				if isFedoraUpdateInfoTitleReliable(ref.Title) {
					ids = util.CveIDPattern.FindAllString(ref.Title, -1)
					if ids == nil {
						// try to correct CVE-ID from description, if title has no CVE-ID
						// NOTE: If this implementation causes the result of collecting a lot of incorrect information, fix to remove it
						ids = util.CveIDPattern.FindAllString(update.Description, -1)
					}
				} else {
					var err error
					ids, err = fetchCveIDsFromBugzilla(ref.ID)
					if err != nil {
						return nil, xerrors.Errorf("Failed to fetch CVE-IDs from bugzilla, err: %w", err)
					}
				}
				if ids != nil {
					cveIDs = append(cveIDs, ids...)
				}
			}
			update.CVEIDs = util.UniqueStrings(cveIDs)
			securityUpdate = append(securityUpdate, update)
		}
		updateInfo.UpdateList = securityUpdate
		updateInfos[r.Target] = &updateInfo
	}
	return updateInfos, nil
}

func isFedoraUpdateInfoTitleReliable(title string) bool {
	if variousFlawsPattern.MatchString(title) {
		return false
	}
	// detect unreliable CVE-ID like CVE-01-0001, CVE-aaa-bbb
	return len(util.CveIDPattern.FindAllString(title, -1)) == strings.Count(title, "CVE-")
}

func fetchModuleFeedFilesFedora(reqs []fetchRequest) ([]FetchResult, error) {
	if len(reqs) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

func fetchModulesYamlFedora(results []FetchResult) (fedoraModuleInfosPerVersion, error) {
	log15.Info("start fetch modules.yaml in repomd.xml")
	updateInfoReqs, err := extractInfoFromRepoMd(results, "modules", mimeTypeGzip)
	if err != nil {
		return nil, xerrors.Errorf("Failed to extract modules from xml, err: %w", err)
	}

	if len(updateInfoReqs) == 0 {
		return nil, xerrors.New("No updateinfo field in the repomd")
	}

	results, err = fetchFeedFiles(updateInfoReqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch modules.yaml, err: %w", err)
	}

	yamls := make(fedoraModuleInfosPerVersion, len(results))
	for _, v := range results {
		m, err := parseModulesYamlFedora(v.Body)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse modules.yaml, err: %w", err)
		}
		yamls[v.Target] = m
	}
	return yamls, nil
}

func parseModulesYamlFedora(b []byte) (fedoraModuleInfosPerPackage, error) {
	modules := fedoraModuleInfosPerPackage{}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	var contents []string
	for scanner.Scan() {
		str := scanner.Text()
		switch str {
		case "---":
			{
				contents = []string{}
			}
		case "...":
			{
				var module FedoraModuleInfo
				if err := yaml.NewDecoder(strings.NewReader(strings.Join(contents, "\n"))).Decode(&module); err != nil {
					return nil, xerrors.Errorf("failed to decode module info. err: %w", err)
				}
				if module.Version == 2 {
					modules[module.ConvertToUpdateInfoTitle()] = module
				}
			}
		default:
			{
				contents = append(contents, str)
			}
		}
	}

	return modules, nil
}

func fetchCveIDsFromBugzilla(id string) ([]string, error) {
	req := fetchRequest{
		url:           fmt.Sprintf(bugZillaURL, id),
		logSuppressed: true,
		mimeType:      mimeTypeXML,
	}
	log15.Info("Fetch CVE-ID list from bugzilla.redhat.com", "URL", req.url)
	body, err := fetchFileWithUA(req)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch CVE-ID list, err: %w", err)
	}

	var b bugzillaXML
	if err = xml.Unmarshal(body, &b); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal xml. url: %s, err: %w", req.url, err)
	}

	var reqs []fetchRequest
	for _, v := range b.Blocked {
		req := fetchRequest{
			url:           fmt.Sprintf(bugZillaURL, v),
			concurrently:  true,
			logSuppressed: true,
			mimeType:      mimeTypeXML,
		}
		reqs = append(reqs, req)
	}

	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch CVE-IDs, err: %w", err)
	}

	var ids []string
	for _, result := range results {
		var b bugzillaXML
		if err = xml.Unmarshal(result.Body, &b); err != nil {
			return nil, xerrors.Errorf("Failed to unmarshal xml. url: %s, err: %w", req.url, err)
		}

		if b.Alias != "" {
			ids = append(ids, b.Alias)
		}
	}

	log15.Info(fmt.Sprintf("%d CVE-IDs fetched", len(ids)))
	return ids, nil
}

func extractInfoFromRepoMd(results []FetchResult, rt string, mt mimeType) ([]fetchRequest, error) {
	var updateInfoReqs []fetchRequest
	for _, r := range results {
		var repoMd RepoMd
		if err := xml.NewDecoder(bytes.NewBuffer(r.Body)).Decode(&repoMd); err != nil {
			return nil, xerrors.Errorf("Failed to decode repomd of version %s. err: %w", r.Target, err)
		}

		for _, repo := range repoMd.RepoList {
			if repo.Type != rt {
				continue
			}
			u, err := url.Parse(r.URL)
			if err != nil {
				return nil, xerrors.Errorf("Failed to parse URL in XML. err: %w", err)
			}
			u.Path = strings.Replace(u.Path, "repodata/repomd.xml", repo.Location.Href, 1)
			req := fetchRequest{
				url:          u.String(),
				target:       r.Target,
				mimeType:     mt,
				concurrently: true,
			}
			updateInfoReqs = append(updateInfoReqs, req)
			break
		}
	}
	return updateInfoReqs, nil
}

// uinfoTitle is expected title of xml format as ${name}-${stream}-${version}.${context}
func fetchModuleInfoFromKojiPkgs(arch, uinfoTitle string) (FedoraModuleInfo, error) {
	req, err := newKojiPkgsRequest(arch, uinfoTitle)
	if err != nil {
		return FedoraModuleInfo{}, xerrors.Errorf("Failed to generate request to kojipkgs.fedoraproject.org, err: %w", err)
	}
	result, err := fetchFileWithUA(req)
	if err != nil {
		return FedoraModuleInfo{}, xerrors.Errorf("Failed to fetch from kojipkgs.fedoraproject.org, err: %w", err)
	}
	moduleYaml, err := parseModulesYamlFedora(result)
	if err != nil {
		return FedoraModuleInfo{}, xerrors.Errorf("Failed to parse module text, err: %w", err)
	}
	if yml, ok := moduleYaml[uinfoTitle]; !ok {
		return yml, nil
	}
	return FedoraModuleInfo{}, xerrors.New("Module not found in kojipkgs.fedoraproject.org")
}

func newKojiPkgsRequest(arch, uinfoTitle string) (fetchRequest, error) {
	relIndex := strings.LastIndex(uinfoTitle, "-")
	if relIndex == -1 {
		return fetchRequest{}, xerrors.Errorf("Failed to parse release from title of updateinfo: %s", uinfoTitle)
	}
	rel := uinfoTitle[relIndex+1:]

	verIndex := strings.LastIndex(uinfoTitle[:relIndex], "-")
	if verIndex == -1 {
		return fetchRequest{}, xerrors.Errorf("Failed to parse version from title of updateinfo: %s", uinfoTitle)
	}
	ver := uinfoTitle[verIndex+1 : relIndex]
	name := uinfoTitle[:verIndex]

	req := fetchRequest{
		url:      fmt.Sprintf(kojiPkgURL, name, ver, rel, arch),
		mimeType: mimeTypeTxt,
	}
	return req, nil
}
