package fetcher

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

// FetchFedora fetch OVAL from Fedora
func FetchUpdateInfosFedora(versions []string) (fedoraUpdatesPerVersion, error) {
	reqs, moduleReqs := newFedoraFetchRequests(versions)
	results, err := fetchEverythingFedora(reqs)
	if err != nil {
		return nil, xerrors.Errorf("fetchEverythingFedora: %w", err)
	}

	moduleResults, err := fetchModulesFedora(moduleReqs)
	if err != nil {
		return nil, xerrors.Errorf("fetchModulesFedora: %w", err)
	}
	results.merge(&moduleResults)

	return results, nil
}

func newFedoraFetchRequests(target []string) (reqs, moduleReqs []fetchRequest) {
	const href = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Everything/x86_64/repodata/repomd.xml"
	const moduleHref = "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/Modular/x86_64/repodata/repomd.xml"
	for _, v := range target {
		reqs = append(reqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(href, v),
			mimeType:     mimeTypeXml,
			concurrently: false,
		})
		moduleReqs = append(moduleReqs, fetchRequest{
			target:       v,
			url:          fmt.Sprintf(moduleHref, v),
			mimeType:     mimeTypeXml,
			concurrently: false,
		})
	}
	return
}

func fetchEverythingFedora(reqs []fetchRequest) (fedoraUpdatesPerVersion, error) {
	log15.Info("start fetch data from Everything/x86_64/repodata/repomd.xml")
	feeds, err := fetchFeedFilesFedora(reqs)
	if err != nil {
		return nil, err
	}

	updates, err := fetchUpdateInfosFedora(feeds)
	if err != nil {
		return nil, err
	}

	results, err := parseFetchResultsFedora(updates)
	if err != nil {
		return nil, err
	}

	for version, v := range results {
		log15.Info(fmt.Sprintf("%d CVEs for Fedora %s Fetched", len(v.UpdateList), version))
	}

	return results, nil
}

func fetchModulesFedora(reqs []fetchRequest) (fedoraUpdatesPerVersion, error) {
	log15.Info("start fetch data from Modular/x86_64/repodata/repomd.xml")
	feeds, err := fetchModuleFeedFilesFedora(reqs)
	if err != nil {
		return nil, err
	}

	updates, err := fetchUpdateInfosFedora(feeds)
	if err != nil {
		return nil, err
	}

	moduleYaml, err := fetchModulesYamlFedora(feeds)
	if err != nil {
		return nil, err
	}

	results, err := parseFetchResultsFedora(updates)
	if err != nil {
		return nil, err
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
						return nil, err
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
		return nil, fmt.Errorf("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

func fetchUpdateInfosFedora(results []FetchResult) ([]FetchResult, error) {
	log15.Info("start fetch updateinfo in repomd.xml")
	var updateInfoReqs []fetchRequest
	for _, r := range results {
		var repoMd RepoMd
		if err := xml.NewDecoder(bytes.NewBuffer(r.Body)).Decode(&repoMd); err != nil {
			log15.Warn(fmt.Sprintf("Failed to decode repomd. Skip to fetch version %s", r.Target), "err", err)
			continue
		}

		for _, repo := range repoMd.RepoList {
			if repo.Type == "updateinfo" {
				u, err := url.Parse(r.URL)
				if err != nil {
					return nil, err
				}
				u.Path = strings.Replace(u.Path, "repodata/repomd.xml", repo.Location.Href, 1)
				req := fetchRequest{
					url:          u.String(),
					target:       r.Target,
					mimeType:     mimeTypeXz,
					concurrently: false,
				}
				updateInfoReqs = append(updateInfoReqs, req)
				break
			}
		}
	}

	if len(updateInfoReqs) == 0 {
		return nil, fmt.Errorf("No updateinfo field in the repomd")
	}

	results, err := fetchFeedFiles(updateInfoReqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

func parseFetchResultsFedora(results []FetchResult) (fedoraUpdatesPerVersion, error) {
	updateInfos := make(fedoraUpdatesPerVersion, len(results))
	for _, r := range results {
		var updateInfo FedoraUpdates
		if err := xml.NewDecoder(bytes.NewReader(r.Body)).Decode(&updateInfo); err != nil {
			return nil, err
		}
		var securityUpdate []FedoraUpdateInfo
		for _, update := range updateInfo.UpdateList {
			if update.Type == "security" {
				cveIDs := []string{}
				for _, ref := range update.References {
					id := util.CveIDPattern.FindAllString(ref.Title, -1)
					if id != nil {
						cveIDs = append(cveIDs, id...)
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
		return nil, fmt.Errorf("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}

func fetchModulesYamlFedora(results []FetchResult) (fedoraModuleInfosPerVersion, error) {
	log15.Info("start fetch modules.yaml in repomd.xml")
	var updateInfoReqs []fetchRequest
	for _, r := range results {
		var repoMd RepoMd
		if err := xml.NewDecoder(bytes.NewBuffer(r.Body)).Decode(&repoMd); err != nil {
			log15.Warn(fmt.Sprintf("Failed to decode repomd. Skip to fetch version %s", r.Target), "err", err)
			continue
		}

		for _, repo := range repoMd.RepoList {
			if repo.Type == "modules" {
				u, err := url.Parse(r.URL)
				if err != nil {
					return nil, err
				}
				u.Path = strings.Replace(u.Path, "repodata/repomd.xml", repo.Location.Href, 1)
				req := fetchRequest{
					url:          u.String(),
					target:       r.Target,
					mimeType:     mimeTypeGzip,
					concurrently: false,
				}
				updateInfoReqs = append(updateInfoReqs, req)
				break
			}
		}
	}

	if len(updateInfoReqs) == 0 {
		return nil, fmt.Errorf("No updateinfo field in the repomd")
	}

	results, err := fetchFeedFiles(updateInfoReqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}

	yamls := make(fedoraModuleInfosPerVersion, len(results))
	for _, v := range results {
		m, err := parseModulesYamlFedora(v.Body)
		if err != nil {
			return nil, err
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
				if err != nil && !errors.As(err, &yaml.TypeError{}) {
					return nil, xerrors.Errorf("failed to decode module info: %w", err)
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
