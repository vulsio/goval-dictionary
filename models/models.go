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
	ID uint `gorm:"primary_key"`
	//  Timestamp   time.Time
	Family      string
	OSVersion   string
	Definitions []Definition
	Timestamp   time.Time
}

// Definition : >definitions>definition
type Definition struct {
	ID     uint `gorm:"primary_key"`
	RootID uint `json:"-" xml:"-"`

	DefinitionID  string
	Title         string
	Description   string
	Advisory      Advisory
	Debian        Debian
	AffectedPacks []Package
	References    []Reference
}

// Package affedted
type Package struct {
	ID           uint `gorm:"primary_key"`
	DefinitionID uint `json:"-" xml:"-"`

	Name        string
	Version     string // affected earlier than this version
	NotFixedYet bool   // Ubuntu Only
}

// Reference : >definitions>definition>metadata>reference
type Reference struct {
	ID           uint `gorm:"primary_key"`
	DefinitionID uint `json:"-" xml:"-"`

	Source string
	RefID  string
	RefURL string
}

// Advisory : >definitions>definition>metadata>advisory
type Advisory struct {
	ID           uint `gorm:"primary_key"`
	DefinitionID uint `json:"-" xml:"-"`

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
	ID         uint `gorm:"primary_key"`
	AdvisoryID uint `json:"-" xml:"-"`

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
	ID         uint `gorm:"primary_key"`
	AdvisoryID uint `json:"-" xml:"-"`

	BugzillaID string
	URL        string
	Title      string
}

// Cpe : >definitions>definition>metadata>advisory>affected_cpe_list
type Cpe struct {
	ID         uint `gorm:"primary_key"`
	AdvisoryID uint `json:"-" xml:"-"`

	Cpe string
}

// Debian : >definitions>definition>metadata>debian
type Debian struct {
	ID           uint `gorm:"primary_key"`
	DefinitionID uint `json:"-" xml:"-"`

	CveID    string
	MoreInfo string
	Date     time.Time
}
