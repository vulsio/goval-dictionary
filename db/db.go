package db

import (
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"

	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var db *gorm.DB

// Supported DB dialects.
const (
	dialectSqlite3  = "sqlite3"
	dialectMysql    = "mysql"
	dialectPostgres = "postgres"
)

// OpenDB opens Database
func OpenDB() (err error) {
	db, err = gorm.Open(c.Conf.DBType, c.Conf.DBPath)
	if err != nil {
		if c.Conf.DBType == dialectSqlite3 {
			err = fmt.Errorf("Failed to open DB. datafile: %s, err: %s", c.Conf.DBPath, err)
		} else if c.Conf.DBType == dialectMysql {
			err = fmt.Errorf("Failed to open DB, err: %s", err)
		} else if c.Conf.DBType == dialectPostgres {
			err = fmt.Errorf("Failed to open DB, err: %s", err)
		} else {
			err = fmt.Errorf("Invalid database dialect, %s", c.Conf.DBType)
		}
		return
	}

	db.LogMode(c.Conf.DebugSQL)

	if c.Conf.DBType == dialectSqlite3 {
		db.Exec("PRAGMA journal_mode=WAL;")
	}

	return
}

func recconectDB() error {
	var err error
	if err = db.Close(); err != nil {
		return fmt.Errorf("Failed to close DB. Type: %s, Path: %s, err: %s", c.Conf.DBType, c.Conf.DBPath, err)
	}
	return OpenDB()
}

// MigrateDB migrates Database
func MigrateDB() error {
	if err := db.AutoMigrate(
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
	if err := db.Model(&models.Definition{}).
		AddIndex("idx_definition_root_id", "root_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}

	if err := db.Model(&models.Package{}).
		AddIndex("idx_packages_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&models.Package{}).
		AddIndex("idx_packages_name", "name").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}

	if err := db.Model(&models.Reference{}).
		AddIndex("idx_reference_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&models.Advisory{}).
		AddIndex("idx_advisories_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&models.Cve{}).
		AddIndex("idx_cves_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&models.Bugzilla{}).
		AddIndex("idx_bugzillas_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&models.Cpe{}).
		AddIndex("idx_cpes_advisory_id", "advisory_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&models.Debian{}).
		AddIndex("idx_debian_definition_id", "definition_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&models.Debian{}).
		AddIndex("idx_debian_cve_id", "cve_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	return nil
}

// OvalDB is a interface of RedHat, Debian
type OvalDB interface {
	GetByPackName(string, string) ([]models.Definition, error)
	GetByCveID(string, string) ([]models.Definition, error)
	InsertFetchMeta(models.FetchMeta) error
	InsertOval(*models.Root, models.FetchMeta) error
}

// Base struct of RedHat, Debian
type Base struct {
	Family string
	DB     *gorm.DB
}

// InsertFetchMeta inserts FetchMeta
func (o Base) InsertFetchMeta(meta models.FetchMeta) error {
	tx := db.Begin()

	oldmeta := models.FetchMeta{}
	r := tx.Where(&models.FetchMeta{FileName: meta.FileName}).First(&oldmeta)
	if !r.RecordNotFound() && oldmeta.Timestamp.Equal(meta.Timestamp) {
		return nil
	}

	// Update FetchMeta
	if r.RecordNotFound() {
		if err := tx.Create(&meta).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("Failed to insert FetchMeta: %s", err)
		}
	} else {
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

// NewDB create a OvalDB client
func NewDB(family string, priorityDB ...*gorm.DB) (OvalDB, error) {
	switch family {
	case c.Debian:
		return NewDebian(priorityDB...), nil
	case c.Ubuntu:
		return NewUbuntu(priorityDB...), nil
	case c.RedHat:
		return NewRedHat(priorityDB...), nil
	case c.Oracle:
		return NewOracle(priorityDB...), nil
	default:
		if strings.Contains(family, "suse") {
			suses := []string{
				c.OpenSUSE,
				c.OpenSUSELeap,
				c.SUSEEnterpriseServer,
				c.SUSEEnterpriseDesktop,
				c.SUSEOpenstackCloud,
			}
			found := false
			for _, name := range suses {
				if name == family {
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("Unknown SUSE. Specify from %s: %s",
					suses, family)
			}
			return NewSUSE(family, priorityDB...), nil
		}

		return nil, fmt.Errorf("Unknown OS Type: %s", family)
	}
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName
func GetByPackName(family, osVer, packName string, priorityDB ...*gorm.DB) ([]models.Definition, error) {
	db, err := NewDB(family, priorityDB...)
	if err != nil {
		return nil, err
	}
	return db.GetByPackName(osVer, packName)
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func GetByCveID(family, osVer, cveID string, priorityDB ...*gorm.DB) ([]models.Definition, error) {
	db, err := NewDB(family, priorityDB...)
	if err != nil {
		return nil, err
	}
	return db.GetByCveID(osVer, cveID)
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}
