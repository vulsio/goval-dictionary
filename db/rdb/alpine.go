package rdb

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
)

// Alpine is a struct for DBAccess
type Alpine struct {
	Family string
}

// NewAlpine creates DBAccess
func NewAlpine() *Alpine {
	return &Alpine{Family: config.Alpine}
}

// Name return family name
func (o *Alpine) Name() string {
	return o.Family
}

// InsertOval inserts Alpine secdb information as OVAL format
func (o *Alpine) InsertOval(root *models.Root, meta models.FetchMeta, driver *gorm.DB) error {
	log.Debugf("in alpine")
	tx := driver.Begin()

	old := models.Root{}
	r := tx.Where(&models.Root{Family: root.Family, OSVersion: root.OSVersion}).First(&old)
	if !r.RecordNotFound() {
		// Delete data related to root passed in arg
		defs := []models.Definition{}
		driver.Model(&old).Related(&defs, "Definitions")
		for _, def := range defs {
			adv := models.Advisory{}
			driver.Model(&def).Related(&adv, "Advisory")
			if err := tx.Unscoped().Where("advisory_id = ?", adv.ID).Delete(&models.Cve{}).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("Failed to delete: %s", err)
			}
			if err := tx.Unscoped().Where("definition_id = ?", def.ID).Delete(&models.Advisory{}).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("Failed to delete: %s", err)
			}
			if err := tx.Unscoped().Where("definition_id= ?", def.ID).Delete(&models.Package{}).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("Failed to delete: %s", err)
			}
		}
		if err := tx.Unscoped().Where("root_id = ?", old.ID).Delete(&models.Definition{}).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to delete: %s", err)
		}
		if err := tx.Unscoped().Where("id = ?", old.ID).Delete(&models.Root{}).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to delete: %s", err)
		}
	}

	if err := tx.Create(&root).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("Failed to insert. cve: %s, err: %s",
			pp.Sprintf("%v", root), err)
	}

	if err := tx.Commit().Error; err != nil {
		return err
	}
	return nil
}

// GetByPackName select definitions by packName
func (o *Alpine) GetByPackName(osVer, packName string, driver *gorm.DB) ([]models.Definition, error) {
	osVer = majorMinor(osVer)
	packs := []models.Package{}
	if err := driver.Where(&models.Package{Name: packName}).Find(&packs).Error; err != nil {
		return nil, err
	}

	defs := []models.Definition{}
	for _, p := range packs {
		def := models.Definition{}
		if err := driver.Where("id = ?", p.DefinitionID).Find(&def).Error; err != nil {
			return nil, err
		}

		root := models.Root{}
		if err := driver.Where("id = ?", def.RootID).Find(&root).Error; err != nil {
			return nil, err
		}

		if root.Family == config.Alpine && root.OSVersion == osVer {
			defs = append(defs, def)
		}

		for i, def := range defs {
			adv := models.Advisory{}
			if err := driver.Model(&def).Related(&adv, "Advisory").Error; err != nil {
				return nil, err
			}

			cves := []models.Cve{}
			if err := driver.Model(&adv).Related(&cves, "Cves").Error; err != nil {
				return nil, err
			}

			adv.Cves = cves
			defs[i].Advisory = adv

			packs := []models.Package{}
			if err := driver.Model(&def).Related(&packs, "AffectedPacks").Error; err != nil {
				return nil, err
			}
			defs[i].AffectedPacks = packs

		}
	}

	return defs, nil
}

// GetByCveID select definitions by CveID
func (o *Alpine) GetByCveID(osVer, cveID string, driver *gorm.DB) ([]models.Definition, error) {
	osVer = majorMinor(osVer)
	cves := []models.Cve{}
	if err := driver.Where(&models.Cve{CveID: cveID}).Find(&cves).Error; err != nil {
		return nil, err
	}

	defs := []models.Definition{}
	for _, cve := range cves {
		adv := models.Advisory{}
		if err := driver.Where("id = ?", cve.AdvisoryID).Find(&adv).Error; err != nil {
			return nil, err
		}

		def := models.Definition{}
		if err := driver.Where("id = ?", adv.DefinitionID).Find(&def).Error; err != nil {
			return nil, err
		}

		root := models.Root{}
		if err := driver.Where("id = ?", def.RootID).Find(&root).Error; err != nil {
			return nil, err
		}
		if root.Family == config.Alpine && root.OSVersion == osVer {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		adv := models.Advisory{}
		if err := driver.Model(&def).Related(&adv, "Advisory").Error; err != nil {
			return nil, err
		}

		cves := []models.Cve{}
		if err := driver.Model(&adv).Related(&cves, "Cves").Error; err != nil {
			return nil, err
		}
		adv.Cves = cves

		defs[i].Advisory = adv

		packs := []models.Package{}
		if err := driver.Model(&def).Related(&packs, "AffectedPacks").Error; err != nil {
			return nil, err
		}
		defs[i].AffectedPacks = packs
		// defs[i].AffectedPacks = filterByMajor(packs, osVer)
	}

	return defs, nil
}
