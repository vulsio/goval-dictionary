package rdb

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
)

// SUSE is a struct of DBAccess
type SUSE struct {
	Family string
}

// NewSUSE creates DBAccess
func NewSUSE(suseType string) *SUSE {
	return &SUSE{Family: suseType}
}

// Name return family name
func (o *SUSE) Name() string {
	return o.Family
}

// InsertOval inserts SUSE OVAL
func (o *SUSE) InsertOval(root *models.Root, meta models.FetchMeta, driver *gorm.DB) error {
	log.Debugf("in suse")
	tx := driver.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log.Infof("  Skip %s %s (Same Timestamp)", root.Family, root.OSVersion)
		return nil
	}
	log.Infof("  Refreshing %s %s...", root.Family, root.OSVersion)

	old := models.Root{}
	r = tx.Where(&models.Root{Family: root.Family, OSVersion: root.OSVersion}).First(&old)
	if !r.RecordNotFound() {
		// Delete data related to root passed in arg
		defs := []models.Definition{}
		driver.Model(&old).Related(&defs, "Definitions")
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

// GetByPackName select definitions by packName
// SUSE : OVAL is separate for each minor version. So select OVAL by major.minimor version.
// http: //ftp.suse.com/pub/projects/security/oval/
func (o *SUSE) GetByPackName(osVer, packName string, driver *gorm.DB) ([]models.Definition, error) {
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

		if root.Family == o.Family && root.OSVersion == osVer {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		packs := []models.Package{}
		if err := driver.Model(&def).Related(&packs, "AffectedPacks").Error; err != nil {
			return nil, err
		}
		defs[i].AffectedPacks = packs

		refs := []models.Reference{}
		if err := driver.Model(&def).Related(&refs, "References").Error; err != nil {
			return nil, err
		}
		defs[i].References = refs
	}

	return defs, nil
}

// GetByCveID select definitions by CveID
// SUSE : OVAL is separate for each minor version. So select OVAL by major.minimor version.
// http: //ftp.suse.com/pub/projects/security/oval/
func (o *SUSE) GetByCveID(osVer, cveID string, driver *gorm.DB) (defs []models.Definition, err error) {
	tmpdefs := []models.Definition{}
	driver.Where(&models.Definition{Title: cveID}).Find(&tmpdefs)
	for _, def := range tmpdefs {
		root := models.Root{}
		if err := driver.Where("id = ?", def.RootID).Find(&root).Error; err != nil {
			return nil, err
		}
		if root.Family != o.Family || root.OSVersion != osVer {
			continue
		}

		packs := []models.Package{}
		if err := driver.Model(&def).Related(&packs, "AffectedPacks").Error; err != nil {
			return nil, err
		}
		def.AffectedPacks = packs

		refs := []models.Reference{}
		if err := driver.Model(&def).Related(&refs, "References").Error; err != nil {
			return nil, err
		}
		def.References = refs

		defs = append(defs, def)
	}
	return
}
