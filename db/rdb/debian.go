package rdb

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
)

// Debian is a struct of DBAccess
type Debian struct {
	Family string
}

// NewDebian creates DBAccess
func NewDebian() *Debian {
	return &Debian{Family: config.Debian}
}

// Name return family name
func (o *Debian) Name() string {
	return o.Family
}

// InsertOval inserts Debian OVAL
func (o *Debian) InsertOval(root *models.Root, meta models.FetchMeta, driver *gorm.DB) error {
	log15.Debug("in Debian")
	tx := driver.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log15.Info("Skip (Same Timestamp)", "Family", root.Family, "Version", root.OSVersion)
		return tx.Rollback().Error
	}
	log15.Info("Refreshing...", "Family", root.Family, "Version", root.OSVersion)

	old := models.Root{}
	r = tx.Where(&models.Root{Family: root.Family, OSVersion: root.OSVersion}).First(&old)
	if !r.RecordNotFound() {
		for _, def := range root.Definitions {
			olddebs := []models.Debian{}
			if r := tx.Where(&models.Debian{CveID: def.Debian.CveID}).Find(&olddebs); r.RecordNotFound() {

				def.RootID = old.ID
				if err := tx.Create(&def).Error; err != nil {
					tx.Rollback()
					return fmt.Errorf("Failed to insert. cve: %s, err: %s",
						pp.Sprintf("%v", root), err)
				}
				continue
			}

			// Delete old records
			for _, olddeb := range olddebs {
				olddef := models.Definition{}
				if r := tx.First(&olddef, olddeb.DefinitionID); r.RecordNotFound() {
					continue
				}

				oldroot := models.Root{}
				if r := tx.First(&oldroot, olddef.RootID); r.RecordNotFound() {
					continue
				}

				if oldroot.Family != root.Family || oldroot.OSVersion != root.OSVersion {
					continue
				}

				log15.Debug("delete", "defid", olddef.ID)

				if err := tx.Unscoped().Where("definition_id= ?", olddef.ID).Delete(&models.Package{}).Error; err != nil {
					tx.Rollback()
					return fmt.Errorf("Failed to delete: %s", err)
				}
				if err := tx.Unscoped().Where("definition_id = ?", olddef.ID).Delete(&models.Reference{}).Error; err != nil {
					tx.Rollback()
					return fmt.Errorf("Failed to delete: %s", err)
				}
				if err := tx.Unscoped().Where("definition_id = ?", olddef.ID).Delete(&models.Debian{}).Error; err != nil {
					tx.Rollback()
					return fmt.Errorf("Failed to delete: %s", err)
				}
				if err := tx.Unscoped().Where("id = ?", olddef.ID).Delete(&models.Definition{}).Error; err != nil {
					tx.Rollback()
					return fmt.Errorf("Failed to delete: %s", err)
				}
			}

			// Insert a new record
			def.RootID = old.ID
			if err := tx.Create(&def).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("Failed to insert. cve: %s, err: %s",
					pp.Sprintf("%v", root), err)
			}
		}
	} else {
		if err := tx.Create(&root).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to insert. cve: %s, err: %s",
				pp.Sprintf("%v", root), err)
		}
	}

	return tx.Commit().Error
}

// GetByPackName select definitions by packName
func (o *Debian) GetByPackName(driver *gorm.DB, osVer, packName, _ string) (defs []models.Definition, err error) {
	// Specify limit number to avoid `too many SQL variable`.
	// https://github.com/future-architect/vuls/issues/886
	limit, tmpDefs := 998, []models.Definition{}
	for i := 0; true; i++ {
		err = driver.Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?",
			config.Debian, major(osVer)).
			Joins("JOIN packages ON packages.definition_id = definitions.id").
			Where("packages.name = ?", packName).
			Limit(limit).Offset(i * limit).
			Preload("Debian").
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
