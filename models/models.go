package models

import (
	"time"

	"github.com/jinzhu/gorm"
)

// Meta has metadata
type Meta struct {
	gorm.Model `json:"-" xml:"-"`
	Timestamp  time.Time
	Family     string
	Release    string
}

// Definition : >definitions>definition
type Definition struct {
	gorm.Model `json:"-" xml:"-"`
	MetaID     uint `json:"-" xml:"-"`

	Title         string
	Description   string
	Advisory      Advisory
	AffectedPacks []Package
	References    []Reference
}

// Package affedted
type Package struct {
	gorm.Model   `json:"-" xml:"-"`
	DefinitionID uint `json:"-" xml:"-"`

	Name    string
	Version string // affected earlier than this version
}

// Reference : >definitions>definition>metadata>reference
type Reference struct {
	gorm.Model   `json:"-" xml:"-"`
	DefinitionID uint `json:"-" xml:"-"`

	Source string
	RefID  string
	RefURL string
}

// Advisory : >definitions>definition>metadata>advisory
type Advisory struct {
	gorm.Model   `json:"-" xml:"-"`
	DefinitionID uint `json:"-" xml:"-"`

	Severity        string
	CveID           string
	Bugzilla        Bugzilla
	AffectedCPEList []string
}

// Bugzilla : >definitions>definition>metadata>advisory>bugzilla
type Bugzilla struct {
	gorm.Model `json:"-" xml:"-"`
	AdvisoryID uint `json:"-" xml:"-"`

	BugzillaID string
	URL        string
	Title      string
}
