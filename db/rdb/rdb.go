package rdb

import (
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"

	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Supported DB dialects.
const (
	DialectSqlite3    = "sqlite3"
	DialectMysql      = "mysql"
	DialectPostgreSQL = "postgres"
)

// Driver is Driver for RDB
type Driver struct {
	name   string
	conn   *gorm.DB
	ovaldb OvalDB
}

// OvalDB is a interface of RedHat, Debian
type OvalDB interface {
	Name() string
	GetByPackName(string, string, *gorm.DB) ([]models.Definition, error)
	GetByCveID(string, string, *gorm.DB) ([]models.Definition, error)
	InsertOval(*models.Root, models.FetchMeta, *gorm.DB) error
}

// NewRDB return RDB driver
func NewRDB(family, dbType, dbpath string, debugSQL bool) (driver *Driver, err error) {
	driver = &Driver{
		name: dbType,
	}
	// when using server command, family is empty.
	if 0 < len(family) {
		if err = driver.NewOvalDB(family); err != nil {
			return
		}
	}

	log.Debugf("Opening DB (%s).", driver.Name())
	if err = driver.OpenDB(dbType, dbpath, debugSQL); err != nil {
		return
	}

	log.Debugf("Migrating DB (%s).", driver.Name())
	if err = driver.MigrateDB(); err != nil {
		return
	}
	return
}

// NewOvalDB create a OvalDB client
func (d *Driver) NewOvalDB(family string) error {
	switch family {
	case c.Debian:
		d.ovaldb = NewDebian()
	case c.Ubuntu:
		d.ovaldb = NewUbuntu()
	case c.RedHat, c.CentOS:
		d.ovaldb = NewRedHat()
	case c.Oracle:
		d.ovaldb = NewOracle()
	case c.OpenSUSE, c.OpenSUSELeap, c.SUSEEnterpriseServer, c.SUSEEnterpriseDesktop, c.SUSEOpenstackCloud:
		d.ovaldb = NewSUSE(family)
	case c.Alpine:
		d.ovaldb = NewAlpine()
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
func (d *Driver) OpenDB(dbType, dbPath string, debugSQL bool) (err error) {
	d.conn, err = gorm.Open(dbType, dbPath)
	if err != nil {
		return fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
	}
	d.conn.LogMode(debugSQL)

	if dbType == DialectSqlite3 {
		d.conn.Exec("PRAGMA journal_mode=WAL;")
	}

	return
}

// MigrateDB migrates Database
func (d *Driver) MigrateDB() error {
	if err := d.conn.AutoMigrate(
		&models.FetchMeta{},
		&models.Root{},
		&models.Definition{},
		&models.Package{},
		&models.Reference{},
		&models.Advisory{},
		&models.Cve{},
		&models.Bugzilla{},
		&models.Cpe{},
		&models.Debian{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	errMsg := "Failed to create index. err: %s"
	if err := d.conn.Model(&models.Definition{}).
		AddIndex("idx_definition_root_id", "root_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}

	if err := d.conn.Model(&models.Package{}).
		AddIndex("idx_packages_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := d.conn.Model(&models.Package{}).
		AddIndex("idx_packages_name", "name").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}

	if err := d.conn.Model(&models.Reference{}).
		AddIndex("idx_reference_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := d.conn.Model(&models.Advisory{}).
		AddIndex("idx_advisories_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := d.conn.Model(&models.Cve{}).
		AddIndex("idx_cves_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := d.conn.Model(&models.Bugzilla{}).
		AddIndex("idx_bugzillas_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := d.conn.Model(&models.Cpe{}).
		AddIndex("idx_cpes_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := d.conn.Model(&models.Debian{}).
		AddIndex("idx_debian_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := d.conn.Model(&models.Debian{}).
		AddIndex("idx_debian_cve_id", "cve_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	return nil
}

// CloseDB close Database
func (d *Driver) CloseDB() (err error) {
	if err = d.conn.Close(); err != nil {
		log.Errorf("Failed to close DB. Type: %s. err: %s", d.name, err)
		return
	}
	return
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName
func (d *Driver) GetByPackName(osVer, packName string) ([]models.Definition, error) {
	return d.ovaldb.GetByPackName(osVer, packName, d.conn)
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func (d *Driver) GetByCveID(osVer, cveID string) ([]models.Definition, error) {
	return d.ovaldb.GetByCveID(osVer, cveID, d.conn)
}

// InsertOval inserts OVAL
func (d *Driver) InsertOval(root *models.Root, meta models.FetchMeta) error {
	return d.ovaldb.InsertOval(root, meta, d.conn)
}

// InsertFetchMeta inserts FetchMeta
func (d *Driver) InsertFetchMeta(meta models.FetchMeta) error {
	tx := d.conn.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		return nil
	}

	if r.RecordNotFound() {
		if err := tx.Create(&meta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to insert FetchMeta: %s", err)
		}
	} else {
		// Update FetchMeta
		oldmeta.Timestamp = meta.Timestamp
		oldmeta.FileName = meta.FileName
		if err := tx.Save(&oldmeta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to update FetchMeta: %s", err)
		}
	}

	tx.Commit()
	return nil
}

// CountDefs counts the number of definitions specified by args
func (d *Driver) CountDefs(osFamily, osVer string) (int, error) {
	switch osFamily {
	case c.Alpine:
		osVer = majorMinor(osVer)
	case c.SUSEEnterpriseServer:
		// SUSE provides OVAL each major.minor
	default:
		osVer = major(osVer)
	}

	root := models.Root{}
	r := d.conn.Where(&models.Root{Family: osFamily, OSVersion: osVer}).First(&root)
	if r.RecordNotFound() {
		return 0, nil
	}
	count := 0
	if err := d.conn.Model(&models.Definition{}).Where(
		"root_id = ?", root.ID).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetLastModified get last modified time of OVAL in roots
func (d *Driver) GetLastModified(osFamily, osVer string) time.Time {
	switch osFamily {
	case c.Alpine:
		osVer = majorMinor(osVer)
	case c.SUSEEnterpriseServer:
		// SUSE provides OVAL each major.minor
	default:
		osVer = major(osVer)
	}

	root := models.Root{}
	r := d.conn.Where(&models.Root{Family: osFamily, OSVersion: osVer}).First(&root)
	if r.RecordNotFound() {
		now := time.Now()
		return now.AddDate(-100, 0, 0)
	}
	return root.Timestamp
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func majorMinor(osVer string) (majorMinorVersion string) {
	ss := strings.Split(osVer, ".")
	return strings.Join(ss[:len(ss)-1], ".")
}
