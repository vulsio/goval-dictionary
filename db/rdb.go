package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// Supported DB dialects.
const (
	dialectSqlite3    = "sqlite3"
	dialectMysql      = "mysql"
	dialectPostgreSQL = "postgres"
)

// RDBDriver is Driver for RDB
type RDBDriver struct {
	name string
	conn *gorm.DB
}

// Name is driver name
func (r *RDBDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger: logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				LogLevel: logger.Silent,
			},
		),
	}

	if debugSQL {
		gormConfig.Logger = logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold: time.Second,
				LogLevel:      logger.Info,
				Colorful:      true,
			},
		)
	}

	switch r.name {
	case dialectSqlite3:
		r.conn, err = gorm.Open(sqlite.Open(dbPath), &gormConfig)
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
	default:
		err = xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
	}

	if err != nil {
		msg := fmt.Sprintf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
		if r.name == dialectSqlite3 {
			switch err.(sqlite3.Error).Code {
			case sqlite3.ErrLocked, sqlite3.ErrBusy:
				return true, fmt.Errorf(msg)
			}
		}
		return false, fmt.Errorf(msg)
	}

	if r.name == dialectSqlite3 {
		r.conn.Exec("PRAGMA foreign_keys = ON")
	}
	return false, nil
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.FetchMeta{},
		&models.FileMeta{},
		&models.Root{},
		&models.Definition{},
		&models.Package{},
		&models.Reference{},
		&models.Advisory{},
		&models.Cve{},
		&models.Bugzilla{},
		&models.Cpe{},
		&models.Debian{},
	); err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	return nil
}

// CloseDB close Database
func (r *RDBDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}

	var sqlDB *sql.DB
	if sqlDB, err = r.conn.DB(); err != nil {
		return xerrors.Errorf("Failed to get DB Object. err : %w", err)
	}
	if err = sqlDB.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName
func (r *RDBDriver) GetByPackName(family, osVer, packName, arch string) ([]models.Definition, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return nil, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	q := r.conn.
		Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", family, osVer).
		Joins("JOIN packages ON packages.definition_id = definitions.id").
		Preload("Advisory").
		Preload("Advisory.Cves").
		Preload("Advisory.Bugzillas").
		Preload("Advisory.AffectedCPEList").
		Preload("References")

	if family == c.Debian {
		q = q.Preload("Debian")
	}

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

	if family == c.RedHat {
		for i := range defs {
			defs[i].AffectedPacks = filterByRedHatMajor(defs[i].AffectedPacks, major(osVer))
		}
	}

	return defs, nil
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func (r *RDBDriver) GetByCveID(family, osVer, cveID, arch string) ([]models.Definition, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return nil, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	q := r.conn.
		Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", family, osVer).
		Joins("JOIN advisories ON advisories.definition_id = definitions.id").
		Joins("JOIN cves ON cves.advisory_id = advisories.id").
		Where("cves.cve_id = ?", cveID).
		Preload("Advisory").
		Preload("Advisory.Cves").
		Preload("Advisory.Bugzillas").
		Preload("Advisory.AffectedCPEList").
		Preload("References")

	if family == c.Debian {
		q = q.Preload("Debian")
	}

	if arch == "" {
		q = q.Preload("AffectedPacks")
	} else {
		q = q.Preload("AffectedPacks", "arch = ?", arch)
	}

	defs := []models.Definition{}
	if err := q.Find(&defs).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if family == c.RedHat {
		for i := range defs {
			defs[i].AffectedPacks = filterByRedHatMajor(defs[i].AffectedPacks, major(osVer))
		}
	}

	return defs, nil
}

// InsertOval inserts OVAL
func (r *RDBDriver) InsertOval(root *models.Root, meta models.FileMeta) error {
	bar := pb.StartNew(len(root.Definitions))

	family, osVer, err := formatFamilyAndOSVer(root.Family, root.OSVersion)
	if err != nil {
		return fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	log15.Debug(fmt.Sprintf("in %s", family))
	tx := r.conn.Begin()

	oldmeta := models.FileMeta{}
	result := tx.Where(&models.FileMeta{FileName: meta.FileName}).First(&oldmeta)
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return xerrors.Errorf("Failed to get filemeta: %w", result.Error)
	}

	if result.RowsAffected > 0 && oldmeta.Timestamp.Equal(meta.Timestamp) {
		log15.Info("Skip (Same Timestamp)", "Family", family, "Version", osVer)
		return tx.Rollback().Error
	}

	log15.Info("Refreshing...", "Family", family, "Version", osVer)

	old := models.Root{}
	result = tx.Where(&models.Root{Family: family, OSVersion: osVer}).First(&old)
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return xerrors.Errorf("Failed to select old defs: %w", result.Error)
	}

	if result.RowsAffected > 0 {
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

	for i := range root.Definitions {
		root.Definitions[i].RootID = root.ID
	}

	for idx := range chunkSlice(len(root.Definitions), batchSize) {
		if err := tx.Create(root.Definitions[idx.From:idx.To]).Error; err != nil {
			tx.Rollback()
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	return tx.Commit().Error
}

// InsertFileMeta inserts FileMeta
func (r *RDBDriver) InsertFileMeta(meta models.FileMeta) error {
	tx := r.conn.Begin()

	oldmeta := models.FileMeta{}
	result := tx.Where(&models.FileMeta{FileName: meta.FileName}).First(&oldmeta)
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return xerrors.Errorf("Failed to get filemeta: %w", result.Error)
	}

	if oldmeta.Timestamp.Equal(meta.Timestamp) {
		return tx.Rollback().Error
	}

	if result.RowsAffected == 0 {
		if err := tx.Create(&meta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to insert FileMeta: %s", err)
		}
	} else {
		// Update FileMeta
		oldmeta.Timestamp = meta.Timestamp
		oldmeta.FileName = meta.FileName
		if err := tx.Save(&oldmeta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to update FileMeta: %s", err)
		}
	}

	tx.Commit()
	return nil
}

// GetFileMeta :
func (r *RDBDriver) GetFileMeta(meta models.FileMeta) (models.FileMeta, error) {
	filemeta := models.FileMeta{}
	if err := r.conn.Where(&models.FileMeta{FileName: meta.FileName}).Take(&filemeta).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return models.FileMeta{}, fmt.Errorf("Failed to get filemeta: %s", err)
		}
		return models.FileMeta{FileName: meta.FileName, Timestamp: time.Time{}}, nil
	}
	return filemeta, nil
}

// CountDefs counts the number of definitions specified by args
func (r *RDBDriver) CountDefs(family, osVer string) (int, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return 0, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	root := models.Root{}
	if err := r.conn.Where(&models.Root{Family: family, OSVersion: osVer}).Take(&root).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, err
		}
		return 0, nil
	}

	var count int64
	if err := r.conn.Model(&models.Definition{}).Where(
		"root_id = ?", root.ID).Count(&count).Error; err != nil {
		return 0, err
	}
	return int(count), nil
}

// GetLastModified get last modified time of OVAL in roots
func (r *RDBDriver) GetLastModified(family, osVer string) (time.Time, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return time.Time{}, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	root := models.Root{}
	result := r.conn.Where(&models.Root{Family: family, OSVersion: osVer}).First(&root)
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return time.Time{}, xerrors.Errorf("Failed to get root: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		now := time.Now()
		return now.AddDate(-100, 0, 0), nil
	}
	return root.Timestamp, nil
}

// IsGovalDictModelV1 determines if the DB was created at the time of goval-dictionary Model v1
func (r *RDBDriver) IsGovalDictModelV1() (bool, error) {
	return r.conn.Migrator().HasColumn(&models.FetchMeta{}, "file_name"), nil
}

// GetFetchMeta get FetchMeta from Database
func (r *RDBDriver) GetFetchMeta() (fetchMeta *models.FetchMeta, err error) {
	if err = r.conn.Take(&fetchMeta).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return &models.FetchMeta{GovalDictRevision: c.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	return fetchMeta, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RDBDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	fetchMeta.GovalDictRevision = c.Revision
	fetchMeta.SchemaVersion = models.LatestSchemaVersion
	return r.conn.Save(fetchMeta).Error
}
