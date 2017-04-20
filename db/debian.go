package db

import (
	"fmt"

	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
)

// InsertFetchMeta inserts FetchMeta
func InsertFetchMeta(meta models.FetchMeta) error {
	tx := db.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		return nil
	}

	// Update FetchMeta
	if r.RecordNotFound() {
		if err := tx.Create(&meta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to insert FetchMeta: %s", err)
		}
	} else {
		oldmeta.Timestamp = meta.Timestamp
		oldmeta.FileName = meta.FileName
		if err := tx.Save(&oldmeta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to update FetchMeta: %s", err)
		}
	}

	tx.Commit()
	return nil
}

// InsertDebian inserts RedHat OVAL
func InsertDebian(root *models.Root, meta models.FetchMeta) error {
	tx := db.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log.Infof("  Skip (Same Timestamp) %s %s ", root.Family, root.Release)
		return nil
	}
	log.Infof("  Refreshing...  %s %s ", root.Family, root.Release)

	old := models.Root{}
	r = tx.Where(&models.Root{Family: root.Family, Release: root.Release}).First(&old)
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
				if r := db.First(&olddef, olddeb.DefinitionID); r.RecordNotFound() {
					continue
				}

				oldroot := models.Root{}
				if r := db.First(&oldroot, olddef.RootID); r.RecordNotFound() {
					continue
				}

				if oldroot.Family != root.Family || oldroot.Release != root.Release {
					continue
				}

				log.Debugf("delete defid:", olddef.ID)

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

	tx.Commit()
	return nil
}
