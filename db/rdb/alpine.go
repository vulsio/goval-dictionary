package rdb

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
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
	log15.Debug("in alpine")
	tx := driver.Begin()

	old := models.Root{}
	r := tx.Where(&models.Root{Family: root.Family, OSVersion: root.OSVersion}).First(&old)
	if !r.RecordNotFound() {
		// Delete data related to root passed in arg
		defs := []models.Definition{}
		tx.Model(&old).Related(&defs, "Definitions")
		for _, def := range defs {
			adv := models.Advisory{}
			tx.Model(&def).Related(&adv, "Advisory")
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
			if err := tx.Unscoped().Where("definition_id = ?", def.ID).Delete(&models.Reference{}).Error; err != nil {
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

	return tx.Commit().Error
}

// GetByPackName select definitions by packName
func (o *Alpine) GetByPackName(driver *gorm.DB, osVer, packName, _ string) ([]models.Definition, error) {
	osVer = majorMinor(osVer)
	packs := []models.Package{}
	err := driver.Where(&models.Package{Name: packName}).Find(&packs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	defs := []models.Definition{}
	for _, p := range packs {
		def := models.Definition{}
		err = driver.Where("id = ?", p.DefinitionID).Find(&def).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}

		root := models.Root{}
		err = driver.Where("id = ?", def.RootID).Find(&root).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}

		if root.Family == config.Alpine && root.OSVersion == osVer {
			defs = append(defs, def)
		}

		for i, def := range defs {
			adv := models.Advisory{}
			err = driver.Model(&def).Related(&adv, "Advisory").Error
			if err != nil && err != gorm.ErrRecordNotFound {
				return nil, err
			}

			cves := []models.Cve{}
			err = driver.Model(&adv).Related(&cves, "Cves").Error
			if err != nil && err != gorm.ErrRecordNotFound {
				return nil, err
			}

			adv.Cves = cves
			defs[i].Advisory = adv

			packs := []models.Package{}
			err = driver.Model(&def).Related(&packs, "AffectedPacks").Error
			if err != nil && err != gorm.ErrRecordNotFound {
				return nil, err
			}
			defs[i].AffectedPacks = packs

			refs := []models.Reference{}
			err = driver.Model(&def).Related(&refs, "References").Error
			if err != nil && err != gorm.ErrRecordNotFound {
				return nil, err
			}
			defs[i].References = refs
		}
	}

	return defs, nil
}
