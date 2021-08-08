package rdb

import (
	"errors"
	"strings"

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
	if r.Error != nil && !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return xerrors.Errorf("Failed to get fetchmeta: %w", r.Error)
	}

	if r.RowsAffected > 0 && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log15.Info("Skip (Same Timestamp)", "Family", root.Family, "Version", root.OSVersion)
		return tx.Rollback().Error
	}

	log15.Info("Refreshing...", "Family", root.Family, "Version", root.OSVersion)

	old := models.Root{}
	r = tx.Where(&models.Root{Family: root.Family, OSVersion: root.OSVersion}).First(&old)
	if r.Error != nil && !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return xerrors.Errorf("Failed to select old defs: %w", r.Error)
	}

	if r.RowsAffected > 0 {
		// Delete data related to root passed in arg
		defs := []models.Definition{}
		if err := tx.Model(&old).Association("Definitions").Find(&defs); err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to select old defs: %w", err)
		}
		for _, def := range defs {
			if err := tx.Select(clause.Associations).Unscoped().Where("definition_id = ?", def.ID).Delete(&def).Error; err != nil {
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

	for _, chunk := range splitChunkIntoDefinitions(root.Definitions, root.ID, 25) {
		if err := tx.Create(&chunk).Error; err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
	}

	return tx.Commit().Error
}

// GetByPackName select definitions by packName
func (o *SUSE) GetByPackName(driver *gorm.DB, osVer, packName, _ string) ([]models.Definition, error) {
	// SLES: OVAL provided in each major version.
	// OpenSUSE : OVAL is separate for each minor version.
	// http://ftp.suse.com/pub/projects/security/oval/
	if strings.HasPrefix(o.Family, c.SUSEEnterpriseServer) ||
		strings.HasPrefix(o.Family, c.SUSEEnterpriseDesktop) ||
		strings.HasPrefix(o.Family, c.SUSEEnterpriseModule) ||
		strings.HasPrefix(o.Family, c.SUSEEnterpriseWorkstation) ||
		strings.HasPrefix(o.Family, c.SUSEOpenstackCloud) {
		osVer = major(osVer)
	} else {
		osVer = majorDotMinor(osVer)
	}

	packs := []models.Package{}
	err := driver.Where(&models.Package{Name: packName}).Find(&packs).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	defs := []models.Definition{}
	for _, p := range packs {
		def := models.Definition{}
		err = driver.Where("id = ?", p.DefinitionID).Find(&def).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		root := models.Root{}
		err = driver.Where("id = ?", def.RootID).Find(&root).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		if root.Family == o.Family && root.OSVersion == osVer {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		packs := []models.Package{}
		err = driver.Model(&def).Association("AffectedPacks").Find(&packs)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		defs[i].AffectedPacks = packs

		refs := []models.Reference{}
		err = driver.Model(&def).Association("References").Find(&refs)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
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
	if strings.HasPrefix(o.Family, c.SUSEEnterpriseServer) ||
		strings.HasPrefix(o.Family, c.SUSEEnterpriseDesktop) ||
		strings.HasPrefix(o.Family, c.SUSEEnterpriseModule) ||
		strings.HasPrefix(o.Family, c.SUSEEnterpriseWorkstation) ||
		strings.HasPrefix(o.Family, c.SUSEOpenstackCloud) {
		osVer = major(osVer)
	} else {
		osVer = majorDotMinor(osVer)
	}

	err = driver.Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?",
		o.Name(), osVer).
		Joins("JOIN advisories ON advisories.definition_id = definitions.id").
		Joins("JOIN cves ON cves.advisory_id = advisories.id").
		Where("cves.cve_id = ?", cveID).
		Preload("AffectedPacks").
		Preload("References").
		Find(&defs).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return defs, nil
}
