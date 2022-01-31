package fetcher

import (
	"encoding/xml"
	"fmt"
	"strings"

	"golang.org/x/xerrors"
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

// uniquePackages returns deduplicated []Package by Filename
// If Filename is the same, all other information is considered to be the same
func uniquePackages(pkgs []Package) []Package {
	tmp := make(map[string]Package)
	ret := []Package{}
	for _, pkg := range pkgs {
		tmp[pkg.Filename] = pkg
	}
	for _, v := range tmp {
		ret = append(ret, v)
	}
	return ret
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

// Updated has updated at
type Updated struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

// Issued has issued at
type Issued struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

// UpdateInfo has detailed data of Updates
type UpdateInfo struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Updated     Updated     `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	References  []Reference `xml:"references>reference" json:"references,omitempty"`
	CVEIDs      []string    `json:"cveiDs,omitempty"`
}

// AmazonUpdates has a list of ALAS
type AmazonUpdates struct {
	UpdateList []UpdateInfo `xml:"update"`
}

// FedoraUpdateInfo has detailed data of FedoraUpdates
type FedoraUpdateInfo struct {
	UpdateInfo
	Title           string `xml:"title" json:"title,omitempty"`
	Issued          Issued `xml:"issued" json:"issued,omitempty"`
	Type            string `xml:"type,attr" json:"type,omitempty"`
	ModularityLabel string `json:"modularity_label,omitempty"`
}

// FedoraUpdates has a list of Update Info
type FedoraUpdates struct {
	UpdateList []FedoraUpdateInfo `xml:"update"`
}

// FedoraModuleInfo has a data of modules.yaml
type FedoraModuleInfo struct {
	Version int `yaml:"version"`
	Data    struct {
		Name      string `yaml:"name"`
		Stream    string `yaml:"stream"`
		Version   int64  `yaml:"version"`
		Context   string `yaml:"context"`
		Arch      string `yaml:"arch"`
		Artifacts struct {
			Rpms []Rpm `yaml:"rpms"`
		} `yaml:"artifacts"`
	} `yaml:"data"`
}

// ConvertToUpdateInfoTitle generates file name from data of modules.yaml
func (f FedoraModuleInfo) ConvertToUpdateInfoTitle() string {
	return fmt.Sprintf("%s-%s-%d.%s", f.Data.Name, f.Data.Stream, f.Data.Version, f.Data.Context)
}

// ConvertToModularityLabel generates modularity_label from data of modules.yaml
func (f FedoraModuleInfo) ConvertToModularityLabel() string {
	return fmt.Sprintf("%s:%s:%d:%s", f.Data.Name, f.Data.Stream, f.Data.Version, f.Data.Context)
}

// Rpm is a package name of data/artifacts/rpms in modules.yaml
type Rpm string

// NewPackageFromRpm generates Package{} by parsing package name
func (r Rpm) NewPackageFromRpm() (Package, error) {
	filename := strings.TrimSuffix(string(r), ".rpm")

	archIndex := strings.LastIndex(filename, ".")
	if archIndex == -1 {
		return Package{}, xerrors.Errorf("Failed to parse arch from filename: %s", filename)
	}
	arch := filename[archIndex+1:]

	relIndex := strings.LastIndex(filename[:archIndex], "-")
	if relIndex == -1 {
		return Package{}, xerrors.Errorf("Failed to parse release from filename: %s", filename)
	}
	rel := filename[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(filename[:relIndex], "-")
	if verIndex == -1 {
		return Package{}, xerrors.Errorf("Failed to parse version from filename: %s", filename)
	}
	ver := filename[verIndex+1 : relIndex]

	epochIndex := strings.Index(ver, ":")
	var epoch string
	if epochIndex == -1 {
		epoch = "0"
	} else {
		epoch = ver[:epochIndex]
		ver = ver[epochIndex+1:]
	}

	name := filename[:verIndex]
	pkg := Package{
		Name:     name,
		Epoch:    epoch,
		Version:  ver,
		Release:  rel,
		Arch:     arch,
		Filename: filename,
	}
	return pkg, nil
}

type fedoraModuleInfosPerVersion map[string]fedoraModuleInfosPerPackage

type fedoraModuleInfosPerPackage map[string]FedoraModuleInfo

// FedoraUpdatesPerVersion is list of update info per Fedora versions
type FedoraUpdatesPerVersion map[string]*FedoraUpdates

func (source *FedoraUpdatesPerVersion) merge(target *FedoraUpdatesPerVersion) {
	for k, v := range *source {
		if list, ok := (*target)[k]; ok {
			(*source)[k].UpdateList = append(v.UpdateList, list.UpdateList...)
		}
	}
}

type bugzillaXML struct {
	Blocked []string `xml:"bug>blocked" json:"blocked,omitempty"`
	Alias   string   `xml:"bug>alias" json:"alias,omitempty"`
}
