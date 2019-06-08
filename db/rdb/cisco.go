package rdb

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
)

// Cisco is a struct for DBAccess
type Cisco struct {
	Family string
}

// NewCisco creates DBAccess
func NewCisco() *Cisco {
	return &Cisco{Family: config.Cisco}
}

// Name return family name
func (o *Cisco) Name() string {
	return o.Family
}

// InsertOval inserts Cisco OVAL
func (o *Cisco) InsertOval(root *models.Root, meta models.FetchMeta, driver *gorm.DB) error {
	log15.Debug("in Cisco")
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
		// Delete data related to root passed in arg
		defs := []models.Definition{}
		tx.Model(&old).Related(&defs, "Definitions")
		for _, def := range defs {
			deb := models.Debian{}
			tx.Model(&def).Related(&deb, "Debian")
			if err := tx.Unscoped().Where("definition_id = ?", def.ID).Delete(&models.Debian{}).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("Failed to delete: %s", err)
			}
			adv := models.Advisory{}
			tx.Model(&def).Related(&adv, "Advisory")
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
func (o *Cisco) GetByPackName(osVer, packName string, driver *gorm.DB) ([]models.Definition, error) {
	osVer = major(osVer)
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

		if root.Family == config.Cisco && major(root.OSVersion) == osVer {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		deb := models.Debian{}
		err = driver.Model(&def).Related(&deb, "Debian").Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		defs[i].Debian = deb

		adv := models.Advisory{}
		err = driver.Model(&def).Related(&adv, "Advisory").Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
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

// GetByCveID select definitions by CveID
func (o *Cisco) GetByCveID(osVer, cveID string, driver *gorm.DB) ([]models.Definition, error) {
	osVer = major(osVer)

	refs := []models.Reference{}
	err := driver.Where(&models.Reference{Source: "CVE", RefID: cveID}).Find(&refs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	defs := []models.Definition{}
	for _, ref := range refs {
		def := models.Definition{}
		err = driver.Where("id = ?", ref.DefinitionID).Find(&def).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}

		root := models.Root{}
		err = driver.Where("id = ?", def.RootID).Find(&root).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		if root.Family == config.Cisco && major(root.OSVersion) == osVer {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		deb := models.Debian{}
		err = driver.Model(&def).Related(&deb, "Debian").Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		defs[i].Debian = deb

		adv := models.Advisory{}
		err = driver.Model(&def).Related(&adv, "Advisory").Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
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
