package redhat

import (
	"strings"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/models/util"
)

// RepositoryToCPEJSON :
type RepositoryToCPEJSON struct {
	Data map[string]struct {
		Cpes []string
	}
}

// RepositoryToCPE :
type RepositoryToCPE struct {
	ID uint `gorm:"primary_key" json:"-"`

	Repository     string `gorm:"type:varchar(255)"`
	RepositoryCPEs []RepositoryCPE
}

// RepositoryCPE :
type RepositoryCPE struct {
	ID                uint `gorm:"primary_key" json:"-"`
	RepositoryToCPEID uint `json:"-"`

	Cpe string `gorm:"type:varchar(255)"`
}

// ConvertRepositoryToCPEToModel Convert RepositoryToCPEJSON to models
func ConvertRepositoryToCPEToModel(repoToCPEJSON RepositoryToCPEJSON) []RepositoryToCPE {
	repoToCPEs := []RepositoryToCPE{}
	for repo, cpedata := range repoToCPEJSON.Data {
		repoCPEs := []RepositoryCPE{}
		for _, cpe := range cpedata.Cpes {
			repoCPEs = append(repoCPEs, RepositoryCPE{Cpe: cpe})
		}
		repoToCPEs = append(repoToCPEs, RepositoryToCPE{
			Repository:     repo,
			RepositoryCPEs: repoCPEs,
		})
	}
	return repoToCPEs
}

// ConvertToModel Convert OVAL to models
func ConvertToModel(roots []Root) ([]models.Definition, error) {
	defs := []models.Definition{}
	for _, root := range roots {
		tests, err := parseTests(root)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse oval.Tests. err: %w", err)
		}
		defs = append(defs, parseDefinitions(root.Definitions, tests)...)
	}
	return defs, nil
}

// based:
// - https://github.com/aquasecurity/trivy-db/blob/df65ebde46f4ab443fb6f4702b05b8fe6332c356/pkg/vulnsrc/redhat-oval/parse.go
// - https://github.com/aquasecurity/trivy-db/blob/df65ebde46f4ab443fb6f4702b05b8fe6332c356/pkg/vulnsrc/redhat-oval/redhat-oval.go
type rpmInfoTest struct {
	Name           string
	SignatureKeyID SignatureKeyid
	FixedVersion   string
	Arch           []string
}

func parseObjects(ovalObjs Objects) map[string]string {
	objs := map[string]string{}
	for _, obj := range ovalObjs.RpminfoObjects {
		objs[obj.ID] = obj.Name
	}
	return objs
}

func parseStates(objStates States) map[string]RpminfoState {
	states := map[string]RpminfoState{}
	for _, state := range objStates.RpminfoStates {
		states[state.ID] = state
	}
	return states
}

func parseTests(root Root) (map[string]rpmInfoTest, error) {
	objs := parseObjects(root.Objects)
	states := parseStates(root.States)
	tests := map[string]rpmInfoTest{}
	for _, test := range root.Tests.RpminfoTests {
		if test.Check != "at least one" {
			continue
		}

		t, err := followTestRefs(test, objs, states)
		if err != nil {
			return nil, xerrors.Errorf("Failed to follow test refs. err: %w", err)
		}
		tests[test.ID] = t
	}
	return tests, nil
}

func followTestRefs(test RpminfoTest, objects map[string]string, states map[string]RpminfoState) (rpmInfoTest, error) {
	var t rpmInfoTest

	// Follow object ref
	if test.Object.ObjectRef == "" {
		return t, nil
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return t, xerrors.Errorf("Failed to find object ref. object ref: %s, test ref: %s, err: invalid tests data", test.Object.ObjectRef, test.ID)
	}
	t.Name = pkgName

	// Follow state ref
	if test.State.StateRef == "" {
		return t, nil
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return t, xerrors.Errorf("Failed to find state ref. state ref: %s, test ref: %s, err: invalid tests data", test.State.StateRef, test.ID)
	}

	t.SignatureKeyID = state.SignatureKeyid

	if state.Arch.Datatype == "string" && (state.Arch.Operation == "pattern match" || state.Arch.Operation == "equals") {
		t.Arch = strings.Split(state.Arch.Text, "|")
	}

	if state.Evr.Datatype == "evr_string" && state.Evr.Operation == "less than" {
		t.FixedVersion = state.Evr.Text
	}

	return t, nil
}

func parseDefinitions(ovalDefs Definitions, tests map[string]rpmInfoTest) []models.Definition {
	defs := []models.Definition{}
	for _, d := range ovalDefs.Definitions {
		if strings.Contains(d.Description, "** REJECT **") {
			continue
		}

		cves := []models.Cve{}
		for _, c := range d.Advisory.Cves {
			cves = append(cves, models.Cve{
				CveID:  c.CveID,
				Cvss2:  c.Cvss2,
				Cvss3:  c.Cvss3,
				Cwe:    c.Cwe,
				Impact: c.Impact,
				Href:   c.Href,
				Public: c.Public,
			})
		}

		rs := []models.Reference{}
		for _, r := range d.References {
			rs = append(rs, models.Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		cl := []models.Cpe{}
		for _, cpe := range d.Advisory.AffectedCPEList {
			cl = append(cl, models.Cpe{
				Cpe: cpe,
			})
		}

		bs := []models.Bugzilla{}
		for _, b := range d.Advisory.Bugzillas {
			bs = append(bs, models.Bugzilla{
				BugzillaID: b.ID,
				URL:        b.URL,
				Title:      b.Title,
			})
		}

		const timeformat = "2006-01-02"
		issued := util.ParsedOrDefaultTime(timeformat, d.Advisory.Issued.Date)
		updated := util.ParsedOrDefaultTime(timeformat, d.Advisory.Updated.Date)

		def := models.Definition{
			DefinitionID: d.ID,
			Title:        d.Title,
			Description:  d.Description,
			Advisory: models.Advisory{
				Severity:        d.Advisory.Severity,
				Cves:            cves,
				Bugzillas:       bs,
				AffectedCPEList: cl,
				Issued:          issued,
				Updated:         updated,
			},
			Debian:        nil,
			AffectedPacks: collectRedHatPacks(d.Criteria, tests),
			References:    rs,
		}

		if viper.GetBool("no-details") {
			def.Title = ""
			def.Description = ""
			def.Advisory.Severity = ""
			def.Advisory.Bugzillas = []models.Bugzilla{}
			def.Advisory.Issued = time.Time{}
			def.Advisory.Updated = time.Time{}
			def.References = []models.Reference{}
		}

		defs = append(defs, def)
	}
	return defs
}

func collectRedHatPacks(cri Criteria, tests map[string]rpmInfoTest) []models.Package {
	label, pkgs := walkCriterion(cri, tests)
	for i := range pkgs {
		pkgs[i].ModularityLabel = label
	}
	return pkgs
}

func walkCriterion(cri Criteria, tests map[string]rpmInfoTest) (string, []models.Package) {
	var label string
	packages := []models.Package{}

	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Module ") && strings.HasSuffix(c.Comment, " is enabled") {
			label = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Module "), " is enabled")
			continue
		}

		t, ok := tests[c.TestRef]
		if !ok {
			continue
		}

		// Skip red-def:signature_keyid
		if t.SignatureKeyID.Text != "" {
			continue
		}

		packages = append(packages, models.Package{
			Name:    t.Name,
			Version: t.FixedVersion,
		})
	}

	if len(cri.Criterias) == 0 {
		return label, packages
	}

	for _, c := range cri.Criterias {
		l, pkgs := walkCriterion(c, tests)
		if l != "" {
			label = l
		}
		if len(pkgs) != 0 {
			packages = append(packages, pkgs...)
		}
	}
	return label, packages
}
