package rdb

import (
	"errors"

	"github.com/inconshreveable/log15"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	"golang.org/x/xerrors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Alpine is a struct for DBAccess
type Alpine struct {
	Family string
}

// NewAlpine creates DBAccess
func NewAlpine() *Alpine {
	return &Alpine{Family: config.Alpine}
}

// Name return family name
func (o *Alpine) Name() string {
	return o.Family
}

// InsertOval inserts Alpine secdb information as OVAL format
func (o *Alpine) InsertOval(root *models.Root, meta models.FetchMeta, driver *gorm.DB) error {
	log15.Debug("in alpine")
	tx := driver.Begin()

	old := models.Root{}
	r := tx.Where(&models.Root{Family: root.Family, OSVersion: root.OSVersion}).First(&old)
	if !errors.Is(r.Error, gorm.ErrRecordNotFound) {

		defs := []models.Definition{}
		if err := tx.Model(&old).Association("Definitions").Find(&defs); err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to select old defs: %w", err)
		}
		for _, def := range defs {
			adv := models.Advisory{}
			if err := tx.Model(&def).Association("Advisory").Find(&adv); err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to delete: %w", err)
			}
			if err := tx.Select(clause.Associations).Unscoped().Delete(&adv).Error; err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to delete: %w", err)
			}
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
		return xerrors.Errorf("Failed to insert. cve: %s, err: %w",
			pp.Sprintf("%v", root), err)
	}

	if err := tx.Model(&root.Definitions).CreateInBatches(root.Definitions, 100).Error; err != nil {
		tx.Rollback()
		return xerrors.Errorf("Failed to insert. cve: %s, err: %w",
			pp.Sprintf("%v", root), err)
	}

	return tx.Commit().Error
}

// GetByPackName select definitions by packName
func (o *Alpine) GetByPackName(driver *gorm.DB, osVer, packName, _ string) (defs []models.Definition, err error) {
	// Specify limit number to avoid `too many SQL variable`.
	// https://github.com/future-architect/vuls/issues/886
	limit, tmpDefs := 998, []models.Definition{}
	for i := 0; true; i++ {
		err = driver.Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?",
			config.Alpine, majorDotMinor(osVer)).
			Joins("JOIN packages ON packages.definition_id = definitions.id").
			Where("packages.name = ?", packName).
			Limit(limit).Offset(i * limit).
			Preload("Advisory").
			Preload("Advisory.Cves").
			Preload("AffectedPacks").
			Preload("References").
			Find(&tmpDefs).Error

		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		if len(tmpDefs) == 0 {
			break
		}
		defs = append(defs, tmpDefs...)
	}
	return defs, nil
}

// GetByCveID select definition by CveID
func (o *Alpine) GetByCveID(driver *gorm.DB, osVer, cveID string) (defs []models.Definition, err error) {
	err = driver.Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?",
		config.Alpine, majorDotMinor(osVer)).
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
