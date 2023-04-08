package alpine

import "github.com/vulsio/goval-dictionary/models"

// SecDB is a struct of alpine secdb
type SecDB[T PackageType] struct {
	Distroversion string
	Reponame      string
	Urlprefix     string
	Apkurl        string
	Packages      []T
}

// CveIdPackage is a struct of CVE-ID and package
type CveIdPackage struct {
	CveId   string
	Package models.Package
}

// PackageType is interface for a alpine package type
type PackageType interface {
	PackageType1 | PackageType2
	extractCveIdPackages() []CveIdPackage
}

// PackageType1 is the package struct of before alpine 3.14
type PackageType1 struct {
	Pkg struct {
		Name     string
		Secfixes map[string][]string
	}
}

// PackageType2 is the package struct of after alpine 3.14
type PackageType2 struct {
	Pkg struct {
		Name     string
		Secfixes []struct {
			Version string
			Fixes   []struct {
				Identifiers []string
				Linenr      int64
			}
			Linenr int64
		}
	}
}
