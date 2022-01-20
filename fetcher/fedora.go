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

// FetchUpdateInfosFedora fetch OVAL from Fedora
func FetchUpdateInfosFedora(versions []string) (FedoraUpdatesPerVersion, error) {
	reqs, moduleReqs := newFedoraFetchRequests(versions)
	results, err := fetchEverythingFedora(reqs)
	if err != nil {
		return nil, xerrors.Errorf("fetchEverythingFedora. err: %w", err)
	}

	for _, reqs := range moduleReqs {
		moduleResults, err := fetchModulesFedora(reqs)
		if err != nil {
			return nil, xerrors.Errorf("fetchModulesFedora. err: %w", err)
		}
		results.merge(&moduleResults)
	}

	return results, nil
}

func newFedoraFetchRequests(target []string) (reqs []fetchRequest, moduleReqs [][]fetchRequest) {
	const href = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Everything/x86_64/repodata/repomd.xml"
	const moduleHref = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Modular/%s/repodata/repomd.xml"
	moduleArches := []string{"x86_64", "aarch64"}
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(href, v),
			mimeType:     mimeTypeXML,
			concurrently: true,
		})
	}
	for i, arch := range moduleArches {
		moduleReqs = append(moduleReqs, []fetchRequest{})
		for _, v := range target {
			moduleReqs[i] = append(moduleReqs[i], fetchRequest{
				target:       v,
				url:          fmt.Sprintf(moduleHref, v, arch),
				mimeType:     mimeTypeXML,
				concurrently: true,
			})
		}
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

	for version, v := range results {
		log15.Info(fmt.Sprintf("%d CVEs for Fedora %s Fetched", len(v.UpdateList), version))
	}

	return results, nil
}

func fetchModulesFedora(reqs []fetchRequest) (FedoraUpdatesPerVersion, error) {
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
		log15.Info(fmt.Sprintf("%d CVEs for Fedora %s modules Fetched", len(result.UpdateList), version))
		for i, update := range result.UpdateList {
			yml, ok := moduleYaml[version][update.Title]
			if ok {
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
		return nil, fmt.Errorf("No updateinfo field in the repomd")
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
			if update.Type == "security" {
				cveIDs := []string{}
				for _, ref := range update.References {
					var ids []string
					var err error
					if variousFlawsPattern.MatchString(ref.Title) {
						ids, err = fetchCveIDsFromBugzilla(ref.ID)
						if err != nil {
							return nil, xerrors.Errorf("Failed to fetch CVE-IDs from bugzilla, err: %w", err)
						}
					} else {
						ids = util.CveIDPattern.FindAllString(ref.Title, -1)
					}
					if ids != nil {
						cveIDs = append(cveIDs, ids...)
					}
				}
				if len(cveIDs) != 0 {
					cveIDs = util.UniqueStrings(cveIDs)
					update.CVEIDs = cveIDs
					securityUpdate = append(securityUpdate, update)
				}
			}
		}
		updateInfo.UpdateList = securityUpdate
		updateInfos[r.Target] = &updateInfo
	}
	return updateInfos, nil
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
		return nil, fmt.Errorf("No updateinfo field in the repomd")
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
				err := yaml.NewDecoder(strings.NewReader(strings.Join(contents, "\n"))).Decode(&module)
				if err != nil {
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
		url: fmt.Sprintf("https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=%s", id),
	}
	log15.Info("The list of CVE-IDs is omitted, Fetch ID list from bugzilla.redhat.com", "URL", req.url)
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
			url:          fmt.Sprintf("https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=%s", v),
			concurrently: true,
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
			if repo.Type == rt {
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
	}
	return updateInfoReqs, nil
}
