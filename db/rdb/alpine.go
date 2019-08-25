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
func (o *Alpine) GetByPackName(driver *gorm.DB, osVer, packName, _ string) (defs []models.Definition, err error) {
	// Specify limit number to avoid `too many SQL variable`.
	// https://github.com/future-architect/vuls/issues/886
	limit, tmpDefs := 998, []models.Definition{}
	for i := 0; true; i++ {
		err = driver.Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?",
			config.Alpine, majorDotMinor(osVer)).
			Joins("JOIN packages ON packages.definition_id = definitions.id").
			Where("packages.name = ?", packName).
			Limit(limit).Offset(i * limit).
			Preload("Advisory").
			Preload("Advisory.Cves").
			Preload("AffectedPacks").
			Preload("References").
			Find(&defs).Error

		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		if len(tmpDefs) == 0 {
			break
		}
		defs = append(defs, tmpDefs...)
	}
	return defs, nil
}
