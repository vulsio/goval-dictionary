package suse

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/models"
)

type susePackage struct {
	os    string
	osVer string
	pack  models.Package
}

// ConvertToModel Convert OVAL to models
func ConvertToModel(xmlName string, root *Root) (roots []models.Root) {
	m := map[string]map[string]models.Root{}
	for _, ovaldef := range root.Definitions.Definitions {
		if strings.Contains(ovaldef.Description, "** REJECT **") {
			continue
		}

		cves := []models.Cve{}
		switch {
		case strings.Contains(xmlName, "opensuse.1") || strings.Contains(xmlName, "suse.linux.enterprise.desktop.10") || strings.Contains(xmlName, "suse.linux.enterprise.server.9") || strings.Contains(xmlName, "suse.linux.enterprise.server.10"):
			cve := models.Cve{}
			if strings.HasPrefix(ovaldef.Title, "CVE-") {
				cve = models.Cve{
					CveID: ovaldef.Title,
					Href:  fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", ovaldef.Title),
				}
			}
			cves = append(cves, cve)
		default:
			for _, c := range ovaldef.Advisory.Cves {
				cves = append(cves, models.Cve{
					CveID:  c.CveID,
					Cvss3:  c.Cvss3,
					Impact: c.Impact,
					Href:   c.Href,
				})
			}
		}

		references := []models.Reference{}
		for _, r := range ovaldef.References {
			references = append(references, models.Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		cpes := []models.Cpe{}
		for _, cpe := range ovaldef.Advisory.AffectedCPEList {
			cpes = append(cpes, models.Cpe{
				Cpe: cpe,
			})
		}

		bugzillas := []models.Bugzilla{}
		for _, b := range ovaldef.Advisory.Bugzillas {
			bugzillas = append(bugzillas, models.Bugzilla{
				URL:   b.URL,
				Title: b.Title,
			})
		}

		osVerPackages := map[string]map[string][]models.Package{}
		for _, distPack := range collectSUSEPacks(xmlName, ovaldef.Criteria) {
			if _, ok := osVerPackages[distPack.os]; !ok {
				osVerPackages[distPack.os] = map[string][]models.Package{}
			}
			if _, ok := osVerPackages[distPack.os][distPack.osVer]; !ok {
				osVerPackages[distPack.os][distPack.osVer] = append([]models.Package{}, distPack.pack)
			} else {
				osVerPackages[distPack.os][distPack.osVer] = append(osVerPackages[distPack.os][distPack.osVer], distPack.pack)
			}

		}

		for os, verPackages := range osVerPackages {
			for ver, packs := range verPackages {
				def := models.Definition{
					DefinitionID: ovaldef.ID,
					Title:        ovaldef.Title,
					Description:  ovaldef.Description,
					Advisory: models.Advisory{
						Severity:        ovaldef.Advisory.Severity,
						Cves:            append([]models.Cve{}, cves...),           // If the same slice is used, it will only be stored once in the DB
						Bugzillas:       append([]models.Bugzilla{}, bugzillas...), // If the same slice is used, it will only be stored once in the DB
						AffectedCPEList: append([]models.Cpe{}, cpes...),           // If the same slice is used, it will only be stored once in the DB
						Issued:          time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						Updated:         time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
					},
					Debian:        nil,
					AffectedPacks: packs,
					References:    append([]models.Reference{}, references...), // If the same slice is used, it will only be stored once in the DB
				}

				if viper.GetBool("no-details") {
					def.Title = ""
					def.Description = ""
					def.Advisory.Severity = ""
					def.Advisory.AffectedCPEList = []models.Cpe{}
					def.Advisory.Bugzillas = []models.Bugzilla{}
					def.Advisory.Issued = time.Time{}
					def.Advisory.Updated = time.Time{}
					def.References = []models.Reference{}
				}

				if _, ok := m[os]; !ok {
					m[os] = map[string]models.Root{}
				}
				if root, ok := m[os][ver]; !ok {
					m[os][ver] = models.Root{
						Family:      os,
						OSVersion:   ver,
						Definitions: []models.Definition{def},
					}
				} else {
					root.Definitions = append(root.Definitions, def)
					m[os][ver] = root
				}

			}
		}
	}

	for _, v := range m {
		for _, vv := range v {
			roots = append(roots, vv)
		}
	}

	return
}

func collectSUSEPacks(xmlName string, cri Criteria) []susePackage {
	xmlName = strings.TrimSuffix(xmlName, ".xml")

	switch {
	case strings.Contains(xmlName, "opensuse.10") || strings.Contains(xmlName, "opensuse.11") || strings.Contains(xmlName, "suse.linux.enterprise.desktop.10") || strings.Contains(xmlName, "suse.linux.enterprise.server.9") || strings.Contains(xmlName, "suse.linux.enterprise.server.10"):
		return walkSUSEFirst(cri, []susePackage{}, []susePackage{})
	case strings.Contains(xmlName, "opensuse.12"):
		return walkSUSESecond(cri, []susePackage{{os: config.OpenSUSE, osVer: strings.TrimPrefix(xmlName, "opensuse.")}}, []susePackage{})
	default:
		return walkSUSESecond(cri, []susePackage{}, []susePackage{})
	}
}

// comment="(os) is installed"
// comment="(package) less then (ver)"
func walkSUSEFirst(cri Criteria, osVerPackages, acc []susePackage) []susePackage {
	for _, c := range cri.Criterions {
		if strings.HasSuffix(c.Comment, " is installed") {
			comment := strings.TrimSuffix(c.Comment, " is installed")
			var name, version string
			switch {
			case strings.HasPrefix(comment, "suse"):
				comment = strings.TrimPrefix(comment, "suse")
				name = config.OpenSUSE
				version = fmt.Sprintf("%s.%s", comment[:2], comment[2:])
			case strings.HasPrefix(comment, "sled"):
				comment = strings.TrimPrefix(comment, "sled")
				ss := strings.Split(comment, "-")
				switch len(ss) {
				case 0:
					log15.Warn(fmt.Sprintf("Failed to parse. err: unexpected string: %s", comment))
					continue
				case 1:
					name = config.SUSEEnterpriseDesktop
					version = ss[0]
				case 2:
					if strings.HasPrefix(ss[1], "sp") {
						name = config.SUSEEnterpriseDesktop
						version = strings.Join(ss, ".")
					} else {
						name = fmt.Sprintf("%s.%s", config.SUSEEnterpriseDesktop, ss[1])
						version = ss[0]
					}
				default:
					name = fmt.Sprintf("%s.%s", config.SUSEEnterpriseDesktop, strings.Join(ss[2:], "."))
					version = fmt.Sprintf("%s.%s", ss[0], ss[1])
				}
			case strings.HasPrefix(comment, "sles"):
				comment = strings.TrimPrefix(comment, "sles")
				ss := strings.Split(comment, "-")
				switch len(ss) {
				case 0:
					log15.Warn(fmt.Sprintf("Failed to parse. err: unexpected string: %s", comment))
					continue
				case 1:
					name = config.SUSEEnterpriseServer
					version = ss[0]
				case 2:
					if strings.HasPrefix(ss[1], "sp") {
						name = config.SUSEEnterpriseServer
						version = strings.Join(ss, ".")
					} else {
						name = fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, ss[1])
						version = ss[0]
					}
				default:
					name = fmt.Sprintf("%s.%s", config.SUSEEnterpriseServer, strings.Join(ss[2:], "."))
					version = fmt.Sprintf("%s.%s", ss[0], ss[1])
				}
			case strings.HasPrefix(comment, "core9"):
				name = config.SUSEEnterpriseServer
				version = "9"
			}

			osVerPackages = append(osVerPackages, susePackage{
				os:    name,
				osVer: version,
			})
		}

		if strings.Contains(c.Comment, "less than") {
			ss := strings.Split(c.Comment, " less than ")
			if len(ss) != 2 {
				continue
			}

			packName := ss[0]
			packVer := ss[1]
			for _, p := range osVerPackages {
				log15.Debug("append acc package", "os", p.os, "osVer", p.osVer, "pack.Name", packName, "pack.Version", packVer)
				acc = append(acc, susePackage{
					os:    p.os,
					osVer: p.osVer,
					pack: models.Package{
						Name:    packName,
						Version: packVer,
					},
				})
			}
		}
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkSUSEFirst(c, osVerPackages, acc)
	}
	return acc
}

// opensuse13, opensuse.leap, SLED 11 >, SLES 11 >, openstack
func walkSUSESecond(cri Criteria, osVerPackages, acc []susePackage) []susePackage {
	for _, c := range cri.Criterions {
		comment := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			comment = strings.TrimSuffix(c.Comment, " is installed")
		} else {
			continue
		}

		if strings.HasPrefix(comment, "openSUSE") || strings.HasPrefix(comment, "SUSE Linux Enterprise") || strings.HasPrefix(comment, "SUSE OpenStack Cloud") {
			name, version, err := getOSNameVersion(comment)
			if err != nil {
				log15.Warn(err.Error())
				continue
			}
			osVerPackages = append(osVerPackages, susePackage{
				os:    name,
				osVer: version,
			})
		} else {
			ss := strings.Split(comment, "-")
			packName := strings.Join(ss[0:len(ss)-2], "-")
			packVer := strings.Join(ss[len(ss)-2:], "-")
			for _, p := range osVerPackages {
				log15.Debug("append acc package", "os", p.os, "osVer", p.osVer, "pack.Name", packName, "pack.Version", packVer)
				acc = append(acc, susePackage{
					os:    p.os,
					osVer: p.osVer,
					pack: models.Package{
						Name:    packName,
						Version: packVer,
					},
				})
			}
		}
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkSUSESecond(c, osVerPackages, acc)
	}
	return acc
}

func getOSNameVersion(s string) (string, string, error) {
	nameSuffixStack := []string{}
	versionStack := []string{}

	ss := strings.Split(strings.ToLower(s), " ")
	osVerIndex := 0
	for i := len(ss) - 1; i >= 0; i = i - 1 {
		_, err := strconv.ParseFloat(ss[i], 32)
		if err != nil {
			if strings.Contains(ss[i], "-") {
				sss := strings.Split(ss[i], "-")
				for j := len(sss) - 1; j >= 0; j = j - 1 {
					_, err := strconv.ParseInt(sss[j], 10, 0)
					if err != nil {
						if strings.HasPrefix(sss[j], "sp") {
							versionStack = append(versionStack, sss[j])
						} else {
							nameSuffixStack = append(nameSuffixStack, sss[j])
						}
					} else {
						versionStack = append(versionStack, sss[j])
						osVerIndex = i
						break
					}
				}

				if osVerIndex != 0 {
					break
				}
			} else {
				if strings.HasPrefix(ss[i], "sp") {
					versionStack = append(versionStack, ss[i])
				} else {
					nameSuffixStack = append(nameSuffixStack, ss[i])
				}
			}
		} else {
			versionStack = append(versionStack, ss[i])
			osVerIndex = i
			break
		}
	}

	if osVerIndex == 0 {
		return "", "", xerrors.Errorf("Failed to parse OS Name. s: %s", s)
	}

	name := strings.Join(ss[:osVerIndex], ".")
	if len(nameSuffixStack) > 0 {
		for i := 0; i < len(nameSuffixStack)/2; i++ {
			nameSuffixStack[i], nameSuffixStack[len(nameSuffixStack)-i-1] = nameSuffixStack[len(nameSuffixStack)-i-1], nameSuffixStack[i]
		}
		name = fmt.Sprintf("%s.%s", name, strings.Join(nameSuffixStack, "."))
	}

	if len(versionStack) == 0 {
		return "", "", xerrors.Errorf("Failed to parse OS Version. s: %s", s)
	}

	for i := 0; i < len(versionStack)/2; i++ {
		versionStack[i], versionStack[len(versionStack)-i-1] = versionStack[len(versionStack)-i-1], versionStack[i]
	}
	version := strings.Join(versionStack, ".")

	return name, version, nil
}
