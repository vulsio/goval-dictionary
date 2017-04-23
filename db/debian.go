package db

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
)

// Debian is a struct of DBAccess
type Debian struct {
	Base
}

// NewDebian creates DBAccess
func NewDebian(priority ...*gorm.DB) Debian {
	d := Debian{
		Base{
			Family: config.Debian,
		},
	}
	if len(priority) == 1 {
		d.DB = priority[0]
	} else {
		d.DB = db
	}
	return d
}

// InsertOval inserts Debian OVAL
func (o Debian) InsertOval(root *models.Root, meta models.FetchMeta) error {
	tx := o.DB.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log.Infof("  Skip %s %s (Same Timestamp)", root.Family, root.Release)
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
				if r := o.DB.First(&olddef, olddeb.DefinitionID); r.RecordNotFound() {
					continue
				}

				oldroot := models.Root{}
				if r := o.DB.First(&oldroot, olddef.RootID); r.RecordNotFound() {
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

// GetByPackName select definitions by packName
func (o Debian) GetByPackName(release, packName string) ([]models.Definition, error) {
	packs := []models.Package{}
	if err := o.DB.Where(&models.Package{Name: packName}).Find(&packs).Error; err != nil {
		return nil, err
	}

	defs := []models.Definition{}
	for _, p := range packs {
		def := models.Definition{}
		if err := o.DB.Where("id = ?", p.DefinitionID).Find(&def).Error; err != nil {
			return nil, err
		}

		root := models.Root{}
		if err := o.DB.Where("id = ?", def.RootID).Find(&root).Error; err != nil {
			return nil, err
		}

		if root.Family == config.Debian && root.Release == release {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		packs := []models.Package{}
		if err := o.DB.Model(&def).Related(&packs, "AffectedPacks").Error; err != nil {
			return nil, err
		}
		defs[i].AffectedPacks = packs

		refs := []models.Reference{}
		if err := o.DB.Model(&def).Related(&refs, "References").Error; err != nil {
			return nil, err
		}
		defs[i].References = refs

		deb := models.Debian{}
		if err := o.DB.Model(&def).Related(&deb, "Debian").Error; err != nil {
			return nil, err
		}
		defs[i].Debian = deb
	}

	return defs, nil
}

// GetByCveID select definitions by CveID
func (o Debian) GetByCveID(release, cveID string) (defs []models.Definition, err error) {
	tmpdefs := []models.Definition{}
	o.DB.Where(&models.Definition{Title: cveID}).Find(&tmpdefs)
	for _, def := range tmpdefs {
		root := models.Root{}
		if err := o.DB.Where("id = ?", def.RootID).Find(&root).Error; err != nil {
			return nil, err
		}
		if root.Family != config.Debian || root.Release != release {
			continue
		}

		deb := models.Debian{}
		if err := o.DB.Model(&def).Related(&deb, "Debian").Error; err != nil {
			return nil, err
		}
		def.Debian = deb

		packs := []models.Package{}
		if err := o.DB.Model(&def).Related(&packs, "AffectedPacks").Error; err != nil {
			return nil, err
		}
		def.AffectedPacks = packs

		refs := []models.Reference{}
		if err := o.DB.Model(&def).Related(&refs, "References").Error; err != nil {
			return nil, err
		}
		def.References = refs

		defs = append(defs, def)
	}
	return
}
