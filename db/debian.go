package db

import (
	"fmt"

	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
)

// InsertDebian inserts RedHat OVAL
func InsertDebian(meta models.Meta) error {
	tx := db.Begin()

	old := models.Meta{}
	r := tx.Where(&models.Meta{Family: meta.Family, Release: meta.Release}).First(&old)
	if !r.RecordNotFound() {
		//  if old.Timestamp.Equal(meta.Timestamp) {
		//      log.Infof("No need to refresh: %s %s %s", old.Family, old.Release, old.Timestamp)
		//      return nil
		//  }

		for _, def := range meta.Definitions {
			olddebs := []models.Debian{}
			if r := tx.Where(&models.Debian{CveID: def.Debian.CveID}).Find(&olddebs); r.RecordNotFound() {

				def.MetaID = old.ID
				if err := tx.Create(&def).Error; err != nil {
					tx.Rollback()
					return fmt.Errorf("Failed to insert. cve: %s, err: %s",
						pp.Sprintf("%v", meta), err)
				}
				continue
			}

			for _, olddeb := range olddebs {
				//  if def.Debian.Date.Equal(olddeb.Date) {
				//      continue
				//  }

				olddef := models.Definition{}
				if r := db.First(&olddef, olddeb.DefinitionID); r.RecordNotFound() {
					continue
				}

				oldmeta := models.Meta{}
				if r := db.First(&oldmeta, olddef.MetaID); r.RecordNotFound() {
					continue
				}

				if oldmeta.Family != meta.Family || oldmeta.Release != meta.Release {
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
			def.MetaID = old.ID
			if err := tx.Create(&def).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("Failed to insert. cve: %s, err: %s",
					pp.Sprintf("%v", meta), err)
			}
		}
	} else {
		if err := tx.Create(&meta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to insert. cve: %s, err: %s",
				pp.Sprintf("%v", meta), err)
		}
	}

	tx.Commit()
	return nil
}
