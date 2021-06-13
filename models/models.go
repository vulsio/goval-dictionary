package models

import (
	"time"
)

// FetchMeta has metadata
type FetchMeta struct {
	ID uint `gorm:"primary_key"`

	FileName  string `gorm:"type:varchar(255)"`
	Timestamp time.Time
}

// Root is root struct
type Root struct {
	ID          uint   `gorm:"primary_key"`
	Family      string `gorm:"type:varchar(255)"`
	OSVersion   string `gorm:"type:varchar(255)"`
	Definitions []Definition
	Timestamp   time.Time
}

// Definition : >definitions>definition
type Definition struct {
	ID     uint `gorm:"primary_key" json:"-"`
	RootID uint `gorm:"index:idx_definition_root_id" json:"-" xml:"-"`

	DefinitionID  string `gorm:"type:varchar(255)"`
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
	Version         string `gorm:"type:varchar(255)"` // affected earlier than this version
	Arch            string `gorm:"type:varchar(255)"` // Used for Amazon and Oracle Linux
	NotFixedYet     bool   // Ubuntu Only
	ModularityLabel string `gorm:"type:varchar(255)"` // RHEL 8 or later only
}

// Reference : >definitions>definition>metadata>reference
type Reference struct {
	ID           uint `gorm:"primary_key" json:"-"`
	DefinitionID uint `gorm:"index:idx_reference_definition_id" json:"-" xml:"-"`

	Source string `gorm:"type:varchar(255)"`
	RefID  string `gorm:"type:varchar(255)"`
	RefURL string `gorm:"type:varchar(255)"`
}

// Advisory : >definitions>definition>metadata>advisory
type Advisory struct {
	ID           uint `gorm:"primary_key" json:"-"`
	DefinitionID uint `gorm:"index:idx_advisories_definition_id" json:"-" xml:"-"`

	Severity        string `gorm:"type:varchar(255)"`
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

	CveID  string `gorm:"type:varchar(255)"`
	Cvss2  string `gorm:"type:varchar(255)"`
	Cvss3  string `gorm:"type:varchar(255)"`
	Cwe    string `gorm:"type:varchar(255)"`
	Impact string `gorm:"type:varchar(255)"`
	Href   string `gorm:"type:varchar(255)"`
	Public string `gorm:"type:varchar(255)"`
}

// Bugzilla : >definitions>definition>metadata>advisory>bugzilla
// RedHat OVAL
type Bugzilla struct {
	ID         uint `gorm:"primary_key" json:"-"`
	AdvisoryID uint `gorm:"index:idx_bugzillas_advisory_id" json:"-" xml:"-"`

	BugzillaID string `gorm:"type:varchar(255)"`
	URL        string `gorm:"type:varchar(255)"`
	Title      string `gorm:"type:varchar(255)"`
}

// Cpe : >definitions>definition>metadata>advisory>affected_cpe_list
type Cpe struct {
	ID         uint `gorm:"primary_key" json:"-"`
	AdvisoryID uint `gorm:"index:idx_cpes_advisory_id" json:"-" xml:"-"`

	Cpe string `gorm:"type:varchar(255)"`
}

// Debian : >definitions>definition>metadata>debian
type Debian struct {
	ID           uint `gorm:"primary_key" json:"-"`
	DefinitionID uint `gorm:"index:idx_debian_definition_id" json:"-" xml:"-"`

	CveID    string `gorm:"type:varchar(255);index:idx_debian_cve_id"`
	MoreInfo string `gorm:"type:text"`

	Date time.Time
}
