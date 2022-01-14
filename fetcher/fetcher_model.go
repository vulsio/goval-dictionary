package fetcher

import "encoding/xml"

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

// UpdateInfo has a list of ALAS
type AmazonUpdates struct {
	UpdateList []UpdateInfo `xml:"update"`
}

// FedoraUpdate has detailed data of FedoraUpdates
type FedoraUpdateInfo struct {
	UpdateInfo
	Issued Issued `xml:"issued" json:"issued,omitempty"`
	Type   string `xml:"type,attr" json:"type,omitempty"`
}

// FedoraUpdates has a list of Update Info
type FedoraUpdates struct {
	UpdateList []FedoraUpdateInfo `xml:"update"`
}
