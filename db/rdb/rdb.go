package rdb

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	sqlite3 "github.com/mattn/go-sqlite3"
	"golang.org/x/xerrors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Supported DB dialects.
const (
	DialectSqlite3    = "sqlite3"
	DialectMysql      = "mysql"
	DialectPostgreSQL = "postgres"
)

// Driver is Driver for RDB
type Driver struct {
	name string
	conn *gorm.DB
}

// OvalDB is a interface of RedHat, Debian
type OvalDB interface {
	Name() string
	GetByPackName(*gorm.DB, string, string, string) ([]models.Definition, error)
	GetByCveID(*gorm.DB, string, string, string) ([]models.Definition, error)
	InsertOval(*models.Root, models.FileMeta, *gorm.DB) error
}

var ovalMap = map[string]OvalDB{}

// NewRDB return RDB driver
func NewRDB(family, dbType, dbpath string, debugSQL bool) (driver *Driver, locked bool, err error) {
	driver = &Driver{
		name: dbType,
	}
	// when using server command, family is empty.
	if 0 < len(family) {
		if err = driver.NewOvalDB(family); err != nil {
			return nil, false, err
		}
	}

	if locked, err = driver.OpenDB(dbType, dbpath, debugSQL); err != nil {
		return nil, locked, err
	}

	isV1 := driver.IsGovalDictModelV1()
	if err != nil {
		log15.Error("Failed to IsGovalDictModelV1.", "err", err)
		return nil, false, err
	}
	if isV1 {
		log15.Error("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again")
		return nil, false, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err = driver.MigrateDB(); err != nil {
		return nil, false, err
	}
	return driver, false, nil
}

// NewOvalDB create a OvalDB client
func (d *Driver) NewOvalDB(family string) error {
	if _, ok := ovalMap[family]; ok {
		return nil
	}

	// thread safety :
	// enter a 'critical section' when modifying the global ovalMap
	// otherwise a fatal 'concurrent map write' will occur and make the program crash
	var mutex = &sync.Mutex{}
	mutex.Lock()
	defer mutex.Unlock()

	switch family {
	case c.Debian:
		ovalMap[c.Debian] = NewDebian()
	case c.Ubuntu:
		ovalMap[c.Ubuntu] = NewUbuntu()
	case c.Oracle:
		ovalMap[c.Oracle] = NewOracle()
	case c.Alpine:
		ovalMap[c.Alpine] = NewAlpine()
	case c.Amazon:
		ovalMap[c.Amazon] = NewAmazon()
	case c.RedHat, c.CentOS:
		ovalMap[family] = NewRedHat()
	case c.OpenSUSE, c.OpenSUSELeap, c.SUSEEnterpriseServer, c.SUSEEnterpriseDesktop, c.SUSEOpenstackCloud:
		ovalMap[family] = NewSUSE(family)
	default:
		if strings.Contains(family, "suse") {
			suses := []string{
				c.OpenSUSE,
				c.OpenSUSELeap,
				c.SUSEEnterpriseServer,
				c.SUSEEnterpriseDesktop,
				c.SUSEOpenstackCloud,
			}
			return fmt.Errorf("Unknown SUSE. Specify from %s: %s", suses, family)
		}
		return fmt.Errorf("Unknown OS Type: %s", family)
	}
	return nil
}

// Name is driver name
func (d *Driver) Name() string {
	return d.name
}

// OpenDB opens Database
func (d *Driver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   logger.Default.LogMode(logger.Silent),
	}

	if debugSQL {
		gormConfig.Logger = logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold: time.Second,
				LogLevel:      logger.Info,
				Colorful:      true,
			},
		)
	}

	switch d.name {
	case DialectSqlite3:
		d.conn, err = gorm.Open(sqlite.Open(dbPath), &gormConfig)
	case DialectMysql:
		d.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
	case DialectPostgreSQL:
		d.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
	default:
		err = xerrors.Errorf("Not Supported DB dialects. r.name: %s", d.name)
	}

	if err != nil {
		if dbType == DialectSqlite3 {
			switch err.(sqlite3.Error).Code {
			case sqlite3.ErrLocked, sqlite3.ErrBusy:
				return true, err
			}
		}
		return false, fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
	}

	return false, nil
}

// MigrateDB migrates Database
func (d *Driver) MigrateDB() error {
	if err := d.conn.AutoMigrate(
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
	); err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	return nil
}

// CloseDB close Database
func (d *Driver) CloseDB() (err error) {
	if d.conn == nil {
		return
	}

	var sqlDB *sql.DB
	if sqlDB, err = d.conn.DB(); err != nil {
		return xerrors.Errorf("Failed to get DB Object. err : %w", err)
	}
	if err = sqlDB.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", d.name, err)
	}
	return
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName
func (d *Driver) GetByPackName(family, osVer, packName, arch string) ([]models.Definition, error) {
	switch family {
	case c.CentOS:
		family = c.RedHat
	case c.Raspbian:
		family = c.Debian
	}

	if _, ok := ovalMap[family]; !ok {
		return nil, fmt.Errorf("Unsupported family: %s", family)
	}

	return ovalMap[family].GetByPackName(d.conn, osVer, packName, arch)
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func (d *Driver) GetByCveID(family, osVer, cveID, arch string) ([]models.Definition, error) {
	if _, ok := ovalMap[family]; !ok {
		return nil, fmt.Errorf("Unsupported family: %s", family)
	}

	return ovalMap[family].GetByCveID(d.conn, osVer, cveID, arch)
}

// InsertOval inserts OVAL
func (d *Driver) InsertOval(family string, root *models.Root, meta models.FileMeta) error {
	if _, ok := ovalMap[family]; !ok {
		return fmt.Errorf("Unsupported family: %s", family)
	}

	return ovalMap[family].InsertOval(root, meta, d.conn)
}

// InsertFileMeta inserts FileMeta
func (d *Driver) InsertFileMeta(meta models.FileMeta) error {
	tx := d.conn.Begin()

	oldmeta := models.FileMeta{}
	r := tx.Where(&models.FileMeta{FileName: meta.FileName}).First(&oldmeta)
	if r.Error != nil && !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return xerrors.Errorf("Failed to get filemeta: %w", r.Error)
	}

	if oldmeta.Timestamp.Equal(meta.Timestamp) {
		return tx.Rollback().Error
	}

	if r.RowsAffected == 0 {
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

// CountDefs counts the number of definitions specified by args
func (d *Driver) CountDefs(osFamily, osVer string) (int, error) {
	switch osFamily {
	case c.Alpine:
		osVer = majorDotMinor(osVer)
	case c.Amazon:
		osVer = getAmazonLinux1or2(osVer)
	default:
		osVer = major(osVer)
	}

	root := models.Root{}
	r := d.conn.Where(&models.Root{Family: osFamily, OSVersion: osVer}).First(&root)
	if r.Error != nil && !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		return 0, nil
	}

	var count int64
	if err := d.conn.Model(&models.Definition{}).Where(
		"root_id = ?", root.ID).Count(&count).Error; err != nil {
		return 0, err
	}
	return int(count), nil
}

// GetLastModified get last modified time of OVAL in roots
func (d *Driver) GetLastModified(osFamily, osVer string) (time.Time, error) {
	switch osFamily {
	case c.Alpine:
		osVer = majorDotMinor(osVer)
	case c.Amazon:
		osVer = getAmazonLinux1or2(osVer)
	default:
		osVer = major(osVer)
	}

	root := models.Root{}
	r := d.conn.Where(&models.Root{Family: osFamily, OSVersion: osVer}).First(&root)
	if r.Error != nil && !errors.Is(r.Error, gorm.ErrRecordNotFound) {
		return time.Time{}, xerrors.Errorf("Failed to get root: %w", r.Error)
	}

	if r.RowsAffected == 0 {
		now := time.Now()
		return now.AddDate(-100, 0, 0), nil
	}
	return root.Timestamp, nil
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func majorDotMinor(osVer string) (majorMinorVersion string) {
	ss := strings.Split(osVer, ".")
	if len(ss) < 3 {
		return osVer
	}
	return strings.Join(ss[:2], ".")
}

// getAmazonLinux2 returns AmazonLinux1 or 2
func getAmazonLinux1or2(osVersion string) string {
	ss := strings.Fields(osVersion)
	if ss[0] == "2" {
		return "2"
	}
	return "1"
}

func splitChunkIntoDefinitions(definitions []models.Definition, rootID uint, chunkSize int) (chunks [][]models.Definition) {
	for i := range definitions {
		definitions[i].RootID = rootID
	}

	for chunkSize < len(definitions) {
		definitions, chunks = definitions[chunkSize:], append(chunks, definitions[0:chunkSize:chunkSize])
	}

	return append(chunks, definitions)
}

// IsGovalDictModelV1 determines if the DB was created at the time of goval-dictionary Model v1
func (d *Driver) IsGovalDictModelV1() bool {
	return d.conn.Migrator().HasColumn(&models.FetchMeta{}, "file_name")
}

// GetFetchMeta get FetchMeta from Database
func (d *Driver) GetFetchMeta() (fetchMeta *models.FetchMeta, err error) {
	if err = d.conn.Take(&fetchMeta).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return &models.FetchMeta{GovalDictRevision: c.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	return fetchMeta, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (d *Driver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	fetchMeta.GovalDictRevision = c.Revision
	fetchMeta.SchemaVersion = models.LatestSchemaVersion
	return d.conn.Save(fetchMeta).Error
}
