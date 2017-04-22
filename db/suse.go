package db

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/labstack/gommon/log"
)

// SUSE is a struct of DBAccess
type SUSE struct {
	Base
}

// NewSUSE creates DBAccess
func NewSUSE(suseType string, priority ...*gorm.DB) Debian {
	d := Debian{
		Base{
			Family: suseType,
		},
	}
	if len(priority) == 1 {
		d.DB = priority[0]
	} else {
		d.DB = db
	}
	return d
}

// InsertOval inserts SUSE OVAL
func (o SUSE) InsertOval(root *models.Root, meta models.FetchMeta) error {
	tx := o.DB.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log.Infof("  Skip (Same Timestamp)")
		return nil
	}
	log.Infof("  Refreshing...")

	old := models.Root{}
	r = tx.Where(&models.Root{Family: root.Family, Release: root.Release}).First(&old)
	if !r.RecordNotFound() {
		// Delete data related to root passed in arg
		defs := []models.Definition{}
		o.DB.Model(&old).Related(&defs, "Definitions")
		for _, def := range defs {
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

	if err := tx.Commit().Error; err != nil {
		return err
	}
	return nil
}
