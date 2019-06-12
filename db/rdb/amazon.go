package rdb

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
)

// Amazon is a struct for DBAccess
type Amazon struct {
	Family string
}

// NewAmazon creates DBAccess
func NewAmazon() *Amazon {
	return &Amazon{Family: config.Amazon}
}

// Name return family name
func (o *Amazon) Name() string {
	return o.Family
}

// InsertOval inserts Amazon ALAS information as OVAL format
func (o *Amazon) InsertOval(root *models.Root, meta models.FetchMeta, driver *gorm.DB) error {
	log15.Debug("in Amazon")
	tx := driver.Begin()

	old := models.Root{}
	r := tx.Where(&models.Root{
		Family:    root.Family,
		OSVersion: root.OSVersion,
	}).First(&old)
	if !r.RecordNotFound() {
		// Delete data related to root passed via arg
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
func (o *Amazon) GetByPackName(driver *gorm.DB, osVer, packName, arch string) ([]models.Definition, error) {
	if arch == "" {
		return nil, fmt.Errorf("Arch have to be passed via arg for fileter packages")
	}
	packs := []models.Package{}
	err := driver.Where(&models.Package{
		Name: packName,
		Arch: arch,
	}).Find(&packs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	uniqDefs := map[string]models.Definition{}
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

		if root.Family == config.Amazon && root.OSVersion == getAmazonLinux1or2(osVer) {
			uniqDefs[def.DefinitionID] = def
		}
	}

	defs := []models.Definition{}
	for _, def := range uniqDefs {
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

	return defs, nil
}
