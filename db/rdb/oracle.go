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

// Oracle is a struct of DBAccess
type Oracle struct {
	Family string
}

// NewOracle creates DBAccess
func NewOracle() *Oracle {
	return &Oracle{Family: config.Oracle}
}

// Name return family name
func (o *Oracle) Name() string {
	return o.Family
}

// InsertOval inserts Oracle OVAL
func (o *Oracle) InsertOval(root *models.Root, meta models.FileMeta, driver *gorm.DB) error {
	log15.Debug("in Oracle")
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
func (o *Oracle) GetByPackName(driver *gorm.DB, osVer, packName, arch string) ([]models.Definition, error) {
	q := driver.
		Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", config.Oracle, major(osVer)).
		Joins("JOIN packages ON packages.definition_id = definitions.id").
		Preload("Advisory").
		Preload("Advisory.Cves").
		Preload("Advisory.Bugzillas").
		Preload("Advisory.AffectedCPEList").
		Preload("References")

	if arch == "" {
		q = q.Where("`packages`.`name` = ?", packName).Preload("AffectedPacks")
	} else {
		q = q.Where("`packages`.`name` = ? AND `packages`.`arch` = ?", packName, arch).Preload("AffectedPacks", "arch = ?", arch)
	}

	// Specify limit number to avoid `too many SQL variable`.
	// https://github.com/future-architect/vuls/issues/886
	defs := []models.Definition{}
	limit, tmpDefs := 998, []models.Definition{}
	for i := 0; true; i++ {
		err := q.
			Limit(limit).Offset(i * limit).
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
func (o *Oracle) GetByCveID(driver *gorm.DB, osVer, cveID, arch string) ([]models.Definition, error) {
	q := driver.
		Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", config.Oracle, major(osVer)).
		Joins("JOIN advisories ON advisories.definition_id = definitions.id").
		Joins("JOIN cves ON cves.advisory_id = advisories.id").
		Where("cves.cve_id = ?", cveID).
		Preload("Advisory").
		Preload("Advisory.Cves").
		Preload("Advisory.Bugzillas").
		Preload("Advisory.AffectedCPEList").
		Preload("AffectedPacks").
		Preload("References")

	if arch == "" {
		q = q.Preload("AffectedPacks")
	} else {
		q = q.Preload("AffectedPacks", "arch = ?", arch)
	}

	defs := []models.Definition{}
	err := q.Find(&defs).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return defs, nil
}
