package models

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/spf13/viper"
	"github.com/ymomoi/goval-parser/oval"
	"golang.org/x/xerrors"
)

type susePackage struct {
	os    string
	osVer string
	pack  Package
}

// ConvertSUSEToModel Convert OVAL to models
func ConvertSUSEToModel(root *oval.Root) (roots []Root) {
	m := map[string]map[string]Root{}
	for _, ovaldef := range root.Definitions.Definitions {
		if strings.Contains(ovaldef.Description, "** REJECT **") {
			continue
		}
		references := []Reference{}
		for _, r := range ovaldef.References {
			references = append(references, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
		}

		cpes := []Cpe{}
		for _, cpe := range ovaldef.Advisory.AffectedCPEList {
			cpes = append(cpes, Cpe{
				Cpe: cpe,
			})
		}

		cves := []Cve{}
		for _, c := range ovaldef.Advisory.Cves {
			cves = append(cves, Cve{
				CveID:  c.CveID,
				Impact: c.Impact,
				Href:   c.Href,
			})
		}

		bugzillas := []Bugzilla{}
		for _, b := range ovaldef.Advisory.Bugzillas {
			bugzillas = append(bugzillas, Bugzilla{
				URL:   b.URL,
				Title: b.Title,
			})
		}

		osVerPackages := map[string]map[string][]Package{}
		for _, distPack := range collectSUSEPacks(root.XMLName.Local, ovaldef.Criteria) {
			if _, ok := osVerPackages[distPack.os]; !ok {
				osVerPackages[distPack.os] = map[string][]Package{}
			}
			if _, ok := osVerPackages[distPack.os][distPack.osVer]; !ok {
				osVerPackages[distPack.os][distPack.osVer] = append([]Package{}, distPack.pack)
			} else {
				osVerPackages[distPack.os][distPack.osVer] = append(osVerPackages[distPack.os][distPack.osVer], distPack.pack)
			}

		}

		for os, verPackages := range osVerPackages {
			for ver, packs := range verPackages {
				def := Definition{
					DefinitionID: ovaldef.ID,
					Title:        ovaldef.Title,
					Description:  ovaldef.Description,
					Advisory: Advisory{
						Cves:            append([]Cve{}, cves...),
						Severity:        ovaldef.Advisory.Severity,
						AffectedCPEList: append([]Cpe{}, cpes...),
						Bugzillas:       append([]Bugzilla{}, bugzillas...),
					},
					AffectedPacks: packs,
					References:    append([]Reference{}, references...),
				}

				if viper.GetBool("no-details") {
					def.Title = ""
					def.Description = ""
					def.References = []Reference{}
				}

				if _, ok := m[os]; !ok {
					m[os] = map[string]Root{}
				}
				if root, ok := m[os][ver]; !ok {
					m[os][ver] = Root{
						Family:      os,
						OSVersion:   ver,
						Definitions: []Definition{def},
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

func collectSUSEPacks(xmlName string, cri oval.Criteria) []susePackage {
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
func walkSUSEFirst(cri oval.Criteria, osVerPackages, acc []susePackage) []susePackage {
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
					pack: Package{
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
func walkSUSESecond(cri oval.Criteria, osVerPackages, acc []susePackage) []susePackage {
	for _, c := range cri.Criterions {
		comment := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			comment = strings.TrimSuffix(c.Comment, " is installed")
		} else {
			continue
		}

		switch {
		case strings.HasPrefix(comment, "openSUSE"):
			comment = strings.TrimPrefix(comment, "openSUSE ")
			name := config.OpenSUSE
			if strings.HasPrefix(comment, "Leap") {
				name = config.OpenSUSELeap
				comment = strings.TrimPrefix(comment, "Leap ")
			}
			osVerPackages = append(osVerPackages, susePackage{
				os:    name,
				osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
			})
		case strings.HasPrefix(comment, "SUSE Linux Enterprise"):
			comment = strings.TrimPrefix(comment, "SUSE Linux Enterprise ")
			var family string
			switch {
			case strings.HasPrefix(comment, "Desktop"):
				comment = strings.TrimPrefix(comment, "Desktop ")
				family = config.SUSEEnterpriseDesktop
			case strings.HasPrefix(comment, "Server"):
				comment = strings.TrimPrefix(comment, "Server ")
				if strings.HasPrefix(comment, "for") {
					comment = strings.TrimPrefix(comment, "for ")
				}
				family = config.SUSEEnterpriseServer
			case strings.HasPrefix(comment, "Workstation Extension"):
				comment = strings.TrimPrefix(comment, "Workstation Extension ")
				family = config.SUSEEnterpriseWorkstation
			case strings.HasPrefix(comment, "Module for"):
				comment = strings.TrimPrefix(comment, "Module for ")
				family = config.SUSEEnterpriseModule
			default:
				log15.Warn("not support OS Name. currently, only SUSE Linux Enterprise (Desktop|Server|Workstation Extension|Module) is supported", "c.Comment", c.Comment)
			}

			osName, osVer, err := getMoreAccurateOSNameVersion(comment, family)
			if err != nil {
				log15.Warn(err.Error())
				continue
			}

			osVerPackages = append(osVerPackages, susePackage{
				os:    osName,
				osVer: osVer,
			})
		case strings.HasPrefix(comment, "SUSE OpenStack Cloud"):
			comment = strings.TrimPrefix(comment, "SUSE OpenStack Cloud ")
			osName, osVer, err := getMoreAccurateOSNameVersion(comment, config.SUSEOpenstackCloud)
			if err != nil {
				log15.Warn(err.Error())
				continue
			}

			osVerPackages = append(osVerPackages, susePackage{
				os:    osName,
				osVer: osVer,
			})
		default:
			ss := strings.Split(comment, "-")
			packName := strings.Join(ss[0:len(ss)-2], "-")
			packVer := strings.Join(ss[len(ss)-2:], "-")
			for _, p := range osVerPackages {
				log15.Debug("append acc package", "os", p.os, "osVer", p.osVer, "pack.Name", packName, "pack.Version", packVer)
				acc = append(acc, susePackage{
					os:    p.os,
					osVer: p.osVer,
					pack: Package{
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

func getMoreAccurateOSNameVersion(s, osName string) (string, string, error) {
	name := osName
	version := ""

	// s:
	// "12"
	// "12-LTSS"
	// "11-SECURITY"
	// "12 SP1"
	// "12 SP1-LTSS"
	// "11 SP1-CLIENT-TOOLS"
	// "SAP Applications 12"
	// "SAP Applications 12-LTSS"
	// "SAP Applications 11-SECURITY"
	// "SAP Applications 12 SP1"
	// "SAP Applications 12 SP1-LTSS"
	// "SAP Applications 11 SP1-CLIENT-TOOLS"
	// "Python 2 15 SP1"
	ss := strings.Split(s, " ")
	osVerIndex := 0
	isPythonFlag := false
	for i, sss := range ss {
		_, err := strconv.Atoi(sss)
		if err != nil {
			// sss:
			// "SAP"
			// "Applications"
			// "Python"
			// "12-LTSS"
			// "11-SECURITY"
			if strings.Contains(sss, "-") {
				ssss := strings.Split(sss, "-")
				if len(ssss) != 2 {
					return "", "", xerrors.Errorf("Failed to parse. err: (int)-(string) is expected. (actual: %s)", sss)
				}

				_, err = strconv.Atoi(ssss[0])
				if err != nil {
					return "", "", xerrors.Errorf("Failed to parse. err: version is expected. (actual: %s)", ssss[0])
				}

				name = fmt.Sprintf("%s.%s", name, strings.ToLower(ssss[1]))
				version = ssss[0]
				osVerIndex = i
				break
			} else {
				if sss == "Python" {
					isPythonFlag = true
				}
				name = fmt.Sprintf("%s.%s", name, strings.ToLower(sss))
			}
			continue
		}

		if !isPythonFlag {
			version = sss
			osVerIndex = i
			break
		} else {
			name = fmt.Sprintf("%s.%s", name, sss)
			isPythonFlag = false
		}
	}

	if osVerIndex == len(ss)-1 {
		return name, version, nil
	}

	ss = ss[osVerIndex+1:]
	if len(ss) != 1 {
		return "", "", xerrors.Errorf("Failed to parse. err:  unexpected Slice length: %s", ss)
	}

	// ss[0]:
	// "SP1"
	// "SP1-LTSS"
	// "SP1-CLIENT-TOOLS"
	if strings.Contains(ss[0], "-") {
		sss := strings.Split(ss[0], "-")
		if len(sss) < 2 {
			return "", "", xerrors.Errorf("Failed to parse. err: unexpected string: %s", ss[0])
		}

		if sss[0] != "" {
			if strings.HasPrefix(sss[0], "SP") {
				version = fmt.Sprintf("%s.%s", version, strings.ToLower(sss[0]))
			} else {
				return "", "", xerrors.Errorf("Failed to parse. err: unexpected string: %s", ss[0])
			}
		}

		name = fmt.Sprintf("%s.%s", name, strings.ToLower(strings.Join(sss[1:], ".")))
	} else {
		if strings.HasPrefix(ss[0], "SP") {
			version = fmt.Sprintf("%s.%s", version, strings.ToLower(ss[0]))
		} else {
			return "", "", xerrors.Errorf("Failed to parse. err: unexpected string: %s", ss[0])
		}
	}

	return name, version, nil
}
