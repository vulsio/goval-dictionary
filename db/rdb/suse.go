package rdb

import (
	"errors"

	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	"golang.org/x/xerrors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	log15.Debug("in suse")
	tx := driver.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !errors.Is(r.Error, gorm.ErrRecordNotFound) && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log15.Info("Skip (Same Timestamp)", "Family", root.Family, "Version", root.OSVersion)
		return tx.Rollback().Error
	}
	log15.Info("  Refreshing...", "Family", root.Family, "Version", root.OSVersion)

	old := models.Root{}
	r = tx.Where(&models.Root{Family: root.Family, OSVersion: root.OSVersion}).First(&old)
	if !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		// Delete data related to root passed in arg
		defs := []models.Definition{}
		if err := tx.Model(&old).Association("Definitions").Find(&defs); err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to select old defs: %w", err)
		}
		for _, def := range defs {
			if err := tx.Select(clause.Associations).Unscoped().Delete(&def).Error; err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to delete: %w", err)
			}
		}
		if err := tx.Unscoped().Where("root_id = ?", old.ID).Delete(&models.Definition{}).Error; err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to delete: %w", err)
		}
		if err := tx.Unscoped().Where("id = ?", old.ID).Delete(&models.Root{}).Error; err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to delete: %w", err)
		}
	}

	if err := tx.Omit("Definitions").Create(&root).Error; err != nil {
		tx.Rollback()
		return xerrors.Errorf("Failed to insert. err: %w", err)
	}

	if err := tx.Model(&root.Definitions).CreateInBatches(root.Definitions, 100).Error; err != nil {
		tx.Rollback()
		return xerrors.Errorf("Failed to insert. err: %w", err)
	}

	return tx.Commit().Error
}

// GetByPackName select definitions by packName
func (o *SUSE) GetByPackName(driver *gorm.DB, osVer, packName, _ string) ([]models.Definition, error) {
	// SLES: OVAL provided in each major version.
	// OpenSUSE : OVAL is separate for each minor version.
	// http://ftp.suse.com/pub/projects/security/oval/
	switch o.Family {
	case c.SUSEEnterpriseServer,
		c.SUSEEnterpriseDesktop,
		c.SUSEOpenstackCloud:
		osVer = major(osVer)
	}
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

		if root.Family == o.Family && root.OSVersion == osVer {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		packs := []models.Package{}
		err = driver.Model(&def).Association("AffectedPacks").Find(&packs)
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		defs[i].AffectedPacks = packs

		refs := []models.Reference{}
		err = driver.Model(&def).Association("References").Find(&refs)
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		defs[i].References = refs
	}

	return defs, nil
}

// GetByCveID select definitions by CveID
// SUSE : OVAL is separate for each minor version. So select OVAL by major.minimor version.
// http: //ftp.suse.com/pub/projects/security/oval/
func (o *SUSE) GetByCveID(driver *gorm.DB, osVer, cveID string) (defs []models.Definition, err error) {
	err = driver.Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?",
		o.Name(), osVer).
		Joins(`JOIN 'references' ON 'references'.definition_id = definitions.id`).
		Where(`'references'.source = 'CVE' AND 'references'.ref_id = ?`, cveID).
		Preload("AffectedPacks").
		Preload("References").
		Find(&defs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return defs, nil
}
