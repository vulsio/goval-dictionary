package rdb

import (
	"errors"

	"github.com/inconshreveable/log15"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	"golang.org/x/xerrors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	if !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		// Delete data related to root passed via arg
		defs := []models.Definition{}
		if err := tx.Model(&old).Association("Definitions").Find(&defs); err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to select old defs: %w", err)
		}
		for _, def := range defs {
			adv := models.Advisory{}
			if err := tx.Model(&def).Association("Advisory").Find(&adv); err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to select old advs: %w", err)
			}
			if err := tx.Select(clause.Associations).Unscoped().Delete(&adv).Error; err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to delete: %s", err)
			}
			if err := tx.Select(clause.Associations).Unscoped().Delete(&def).Error; err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to delete: %s", err)
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
func (o *Amazon) GetByPackName(driver *gorm.DB, osVer, packName, arch string) ([]models.Definition, error) {
	if arch == "" {
		return nil, xerrors.Errorf("Arch have to be passed via arg for fileter packages")
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
		err = driver.Model(&def).Association("Advisory").Find(&adv)
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}

		cves := []models.Cve{}
		err = driver.Model(&adv).Association("Cves").Find(&cves)
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}

		adv.Cves = cves
		defs[i].Advisory = adv

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

// GetByCveID select definition by CveID
func (o *Amazon) GetByCveID(driver *gorm.DB, osVer, cveID string) (defs []models.Definition, err error) {
	err = driver.Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?",
		config.Amazon, majorDotMinor(osVer)).
		Joins("JOIN advisories ON advisories.definition_id = definitions.id").
		Joins("JOIN cves ON cves.advisory_id = advisories.id").
		Where("cves.cve_id = ?", cveID).
		Preload("Advisory").
		Preload("Advisory.Cves").
		Preload("AffectedPacks").
		Preload("References").
		Find(&defs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return defs, nil
}
