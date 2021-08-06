package models

import (
	"fmt"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/spf13/viper"
	"github.com/ymomoi/goval-parser/oval"
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
		for _, distPack := range collectSUSEPacks(ovaldef.Criteria) {
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

func collectSUSEPacks(cri oval.Criteria) []susePackage {
	return walkSUSE(cri, []susePackage{}, []susePackage{})
}

func walkSUSE(cri oval.Criteria, osVerPackages, acc []susePackage) []susePackage {
	for _, c := range cri.Criterions {
		comment := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			comment = strings.TrimSuffix(c.Comment, " is installed")
		} else {
			continue
		}

		// os or package
		if strings.Contains(comment, "openSUSE") {
			comment = strings.TrimPrefix(comment, "openSUSE ")
			name := config.OpenSUSE
			if strings.Contains(comment, "Leap") {
				name = config.OpenSUSELeap
				comment = strings.TrimPrefix(comment, "Leap ")
			}
			osVerPackages = append(osVerPackages, susePackage{
				os:    name,
				osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
			})
		} else if strings.Contains(comment, "SUSE Linux Enterprise") {
			comment = strings.TrimPrefix(comment, "SUSE Linux Enterprise ")
			if strings.Contains(comment, "Desktop") {
				comment = strings.TrimPrefix(comment, "Desktop ")
				osVerPackages = append(osVerPackages, susePackage{
					os:    config.SUSEEnterpriseDesktop,
					osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
				})
			} else if strings.Contains(comment, "Server") {
				comment = strings.TrimPrefix(comment, "Server ")
				if strings.Contains(comment, "for SAP Applications") {
					comment = strings.TrimPrefix(comment, "for SAP Applications ")
					if strings.Contains(comment, "-LTSS") {
						comment = strings.TrimSuffix(comment, "-LTSS")
						osVerPackages = append(osVerPackages, susePackage{
							os:    config.SUSEEnterpriseServerSAPLTSS,
							osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
						})
					} else {
						osVerPackages = append(osVerPackages, susePackage{
							os:    config.SUSEEnterpriseServerSAP,
							osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
						})
					}
				} else if strings.Contains(comment, "for Raspberry Pi") {
					comment = strings.TrimPrefix(comment, "for Raspberry Pi ")
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseServerRaspberryPi,
						osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
					})
				} else {
					if strings.Contains(comment, "-LTSS") {
						comment = strings.TrimSuffix(comment, "-LTSS")
						osVerPackages = append(osVerPackages, susePackage{
							os:    config.SUSEEnterpriseServerLTSS,
							osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
						})
					} else if strings.Contains(comment, "-BCL") {
						comment = strings.TrimSuffix(comment, "-BCL")
						osVerPackages = append(osVerPackages, susePackage{
							os:    config.SUSEEnterpriseServerBCL,
							osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
						})
					} else if strings.Contains(comment, "-ESPOS") {
						comment = strings.TrimSuffix(comment, "-ESPOS")
						osVerPackages = append(osVerPackages, susePackage{
							os:    config.SUSEEnterpriseServerESPOS,
							osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
						})
					} else if strings.Contains(comment, "-TERADATA") {
						comment = strings.TrimSuffix(comment, "-TERADATA")
						osVerPackages = append(osVerPackages, susePackage{
							os:    config.SUSEEnterpriseServerTERADATA,
							osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
						})
					} else {
						osVerPackages = append(osVerPackages, susePackage{
							os:    config.SUSEEnterpriseServer,
							osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
						})
					}
				}
			} else if strings.Contains(comment, "Workstation Extension") {
				comment = strings.TrimPrefix(comment, "Workstation Extension ")
				osVerPackages = append(osVerPackages, susePackage{
					os:    config.SUSEEnterpriseWorkstation,
					osVer: strings.ToLower(strings.Replace(comment, " ", ".", -1)),
				})
			} else if strings.Contains(comment, "Module for") {
				comment = strings.TrimPrefix(comment, "Module for ")
				if strings.Contains(comment, "Advanced Systems Management") {
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseModuleAdvancedSystemsManagement,
						osVer: strings.TrimPrefix(comment, "Advanced Systems Management "),
					})
				} else if strings.Contains(comment, "Containers") {
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseModuleContainers,
						osVer: strings.TrimPrefix(comment, "Containers "),
					})
				} else if strings.Contains(comment, "High Performance Computing") {
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseModuleHPC,
						osVer: strings.TrimPrefix(comment, "High Performance Computing "),
					})
				} else if strings.Contains(comment, "Legacy") {
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseModuleLegacy,
						osVer: strings.TrimPrefix(comment, "Legacy "),
					})
				} else if strings.Contains(comment, "Public Cloud") {
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseModulePublicCloud,
						osVer: strings.TrimPrefix(comment, "Public Cloud "),
					})
				} else if strings.Contains(comment, "Toolchain") {
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseModuleToolchain,
						osVer: strings.TrimPrefix(comment, "Toolchain "),
					})
				} else if strings.Contains(comment, "Web Scripting") {
					osVerPackages = append(osVerPackages, susePackage{
						os:    config.SUSEEnterpriseModuleWebScripting,
						osVer: strings.TrimPrefix(comment, "Web Scripting "),
					})
				} else {
					log15.Warn("unsupport os name", "osName", fmt.Sprintf("SUSE Linux Enterprise Module for %s", comment))
				}
			} else {
				log15.Warn("unsupport os name", "osName", fmt.Sprintf("SUSE Linux Enterprise %s", comment))
			}

		} else if strings.Contains(comment, "SUSE OpenStack Cloud") {
			osVerPackages = append(osVerPackages, susePackage{
				os:    config.SUSEOpenstackCloud,
				osVer: strings.TrimPrefix(comment, "SUSE OpenStack Cloud "),
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
		acc = walkSUSE(c, osVerPackages, acc)
	}
	return acc
}
