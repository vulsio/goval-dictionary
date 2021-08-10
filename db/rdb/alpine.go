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
func (o *Alpine) InsertOval(root *models.Root, meta models.FileMeta, driver *gorm.DB) error {
	log15.Debug("in alpine")
	tx := driver.Begin()

	oldmeta := models.FileMeta{}
	r := tx.Where(&models.FileMeta{FileName: meta.FileName}).First(&oldmeta)
	if r.Error != nil && !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return xerrors.Errorf("Failed to get filemeta: %w", r.Error)
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
			adv := models.Advisory{}
			if err := tx.Model(&def).Association("Advisory").Find(&adv); err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to delete: %w", err)
			}
			if err := tx.Select(clause.Associations).Unscoped().Where("id = ?", adv.ID).Delete(&adv).Error; err != nil {
				tx.Rollback()
				return xerrors.Errorf("Failed to delete: %w", err)
			}

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

	for _, chunk := range splitChunkIntoDefinitions(root.Definitions, root.ID, 50) {
		if err := tx.Create(&chunk).Error; err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
	}

	return tx.Commit().Error
}

// GetByPackName select definitions by packName
func (o *Alpine) GetByPackName(driver *gorm.DB, osVer, packName, _ string) ([]models.Definition, error) {
	// Specify limit number to avoid `too many SQL variable`.
	// https://github.com/future-architect/vuls/issues/886
	defs := []models.Definition{}
	limit, tmpDefs := 998, []models.Definition{}
	for i := 0; true; i++ {
		err := driver.
			Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", config.Alpine, majorDotMinor(osVer)).
			Joins("JOIN packages ON packages.definition_id = definitions.id").
			Where("packages.name = ?", packName).
			Limit(limit).Offset(i * limit).
			Preload("Advisory").
			Preload("Advisory.Cves").
			Preload("Advisory.Bugzillas").
			Preload("Advisory.AffectedCPEList").
			Preload("AffectedPacks").
			Preload("References").
			Find(&tmpDefs).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
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
func (o *Alpine) GetByCveID(driver *gorm.DB, osVer, cveID, _ string) ([]models.Definition, error) {
	defs := []models.Definition{}
	err := driver.
		Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", config.Alpine, majorDotMinor(osVer)).
		Joins("JOIN advisories ON advisories.definition_id = definitions.id").
		Joins("JOIN cves ON cves.advisory_id = advisories.id").
		Where("cves.cve_id = ?", cveID).
		Preload("Advisory").
		Preload("Advisory.Cves").
		Preload("Advisory.Bugzillas").
		Preload("Advisory.AffectedCPEList").
		Preload("AffectedPacks").
		Preload("References").
		Find(&defs).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return defs, nil
}
