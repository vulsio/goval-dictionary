package models

import (
	"time"
)

// FetchMeta has metadata
type FetchMeta struct {
	ID uint `gorm:"primary_key"`

	FileName  string
	Timestamp time.Time
}

// Root is root struct
type Root struct {
	ID          uint `gorm:"primary_key"`
	Family      string
	OSVersion   string
	Definitions []Definition
	Timestamp   time.Time
}

// Definition : >definitions>definition
type Definition struct {
	ID     uint `gorm:"primary_key" json:"-"`
	RootID uint `gorm:"index:idx_definition_root_id" json:"-" xml:"-"`

	DefinitionID  string
	Title         string `gorm:"type:text"`
	Description   string
	Advisory      Advisory
	Debian        Debian
	AffectedPacks []Package
	References    []Reference
}

// Package affected
type Package struct {
	ID           uint `gorm:"primary_key" json:"-"`
	DefinitionID uint `gorm:"index:idx_packages_definition_id" json:"-" xml:"-"`

	Name            string `gorm:"index:idx_packages_name"`
	Version         string // affected earlier than this version
	Arch            string // Used for Amazon and Oracle Linux
	NotFixedYet     bool   // Ubuntu Only
	ModularityLabel string // RHEL 8 or later only
}

// Reference : >definitions>definition>metadata>reference
type Reference struct {
	ID           uint `gorm:"primary_key" json:"-"`
	DefinitionID uint `gorm:"index:idx_reference_definition_id" json:"-" xml:"-"`

	Source string
	RefID  string
	RefURL string
}

// Advisory : >definitions>definition>metadata>advisory
type Advisory struct {
	ID           uint `gorm:"primary_key" json:"-"`
	DefinitionID uint `gorm:"index:idx_advisories_definition_id" json:"-" xml:"-"`

	Severity        string
	Cves            []Cve
	Bugzillas       []Bugzilla
	AffectedCPEList []Cpe
	Issued          time.Time
	Updated         time.Time
}

// Cve : >definitions>definition>metadata>advisory>cve
// RedHat OVAL
type Cve struct {
	ID         uint `gorm:"primary_key" json:"-"`
	AdvisoryID uint `gorm:"idx_cves_advisory_id" json:"-" xml:"-"`

	CveID  string
	Cvss2  string
	Cvss3  string
	Cwe    string
	Impact string
	Href   string
	Public string
}

// Bugzilla : >definitions>definition>metadata>advisory>bugzilla
// RedHat OVAL
type Bugzilla struct {
	ID         uint `gorm:"primary_key" json:"-"`
	AdvisoryID uint `gorm:"index:idx_bugzillas_advisory_id" json:"-" xml:"-"`

	BugzillaID string
	URL        string
	Title      string
}

// Cpe : >definitions>definition>metadata>advisory>affected_cpe_list
type Cpe struct {
	ID         uint `gorm:"primary_key" json:"-"`
	AdvisoryID uint `gorm:"index:idx_cpes_advisory_id" json:"-" xml:"-"`

	Cpe string
}

// Debian : >definitions>definition>metadata>debian
type Debian struct {
	ID           uint `gorm:"primary_key" json:"-"`
	DefinitionID uint `gorm:"index:idx_debian_definition_id" json:"-" xml:"-"`

	CveID    string `gorm:"index:idx_debian_cve_id"`
	MoreInfo string `gorm:"type:text"`

	Date time.Time
}
