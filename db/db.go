package db

import (
	"fmt"

	"github.com/jinzhu/gorm"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"

	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var db *gorm.DB

// Supported DB dialects.
const (
	dialectSqlite3 = "sqlite3"
	dialectMysql   = "mysql"
)

// OpenDB opens Database
func OpenDB() (err error) {
	db, err = gorm.Open(c.Conf.DBType, c.Conf.DBPath)
	if err != nil {
		if c.Conf.DBType == dialectSqlite3 {
			err = fmt.Errorf("Failed to open DB. datafile: %s, err: %s", c.Conf.DBPath, err)
		} else if c.Conf.DBType == dialectMysql {
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
		&models.Meta{},
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
		AddIndex("idx_definition_meta_id", "meta_id").Error; err != nil {
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

// GetByPackName select OVAL definition related to OS Family, release, packName
func GetByPackName(family, release, packName string, priorityDB ...*gorm.DB) ([]models.Definition, error) {
	var conn *gorm.DB
	if len(priorityDB) == 1 {
		conn = priorityDB[0]
	} else {
		conn = db
	}

	packs := []models.Package{}
	//TODO error
	conn.Where(&models.Package{Name: packName}).Find(&packs)

	defs := []models.Definition{}
	for _, p := range packs {
		def := models.Definition{}
		//TODO error
		db.Where("id = ?", p.DefinitionID).Find(&def)

		meta := models.Meta{}
		//TODO error
		db.Where("id = ?", def.MetaID).Find(&meta)

		if meta.Family == family && meta.Release == release {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		adv := models.Advisory{}
		//TODO error
		db.Model(&def).Related(&adv, "Advisory")

		cves := []models.Cve{}
		//TODO error
		db.Model(&adv).Related(&cves, "Cves")
		adv.Cves = cves

		bugs := []models.Bugzilla{}
		//TODO error
		db.Model(&adv).Related(&bugs, "Bugzillas")
		adv.Bugzillas = bugs

		cpes := []models.Cpe{}
		//TODO error
		db.Model(&adv).Related(&cpes, "AffectedCPEList")
		adv.AffectedCPEList = cpes

		defs[i].Advisory = adv

		packs := []models.Package{}
		//TODO error
		db.Model(&def).Related(&packs, "AffectedPacks")
		defs[i].AffectedPacks = packs

		refs := []models.Reference{}
		//TODO error
		db.Model(&def).Related(&refs, "References")
		defs[i].References = refs
	}

	return defs, nil
}

// GetByCveID select OVAL definition related to OS Family, release, CVE-ID
func GetByCveID(family, release, cveID string, priorityDB ...*gorm.DB) ([]models.Definition, error) {
	var conn *gorm.DB
	if len(priorityDB) == 1 {
		conn = priorityDB[0]
	} else {
		conn = db
	}

	cves := []models.Cve{}
	//TODO error
	conn.Where(&models.Cve{CveID: cveID}).Find(&cves)

	defs := []models.Definition{}
	for _, cve := range cves {

		//TODO error
		adv := models.Advisory{}
		db.Where("id = ?", cve.AdvisoryID).Find(&adv)

		//TODO error
		def := models.Definition{}
		db.Where("id = ?", adv.DefinitionID).Find(&def)

		//TODO error
		meta := models.Meta{}
		db.Where("id = ?", def.MetaID).Find(&meta)
		if meta.Family == family && meta.Release == release {
			defs = append(defs, def)
		}
	}

	for i, def := range defs {
		adv := models.Advisory{}
		//TODO error
		db.Model(&def).Related(&adv, "Advisory")

		cves := []models.Cve{}
		//TODO error
		db.Model(&adv).Related(&cves, "Cves")
		adv.Cves = cves

		bugs := []models.Bugzilla{}
		//TODO error
		db.Model(&adv).Related(&bugs, "Bugzillas")
		adv.Bugzillas = bugs

		cpes := []models.Cpe{}
		//TODO error
		db.Model(&adv).Related(&cpes, "AffectedCPEList")
		adv.AffectedCPEList = cpes

		defs[i].Advisory = adv

		packs := []models.Package{}
		//TODO error
		db.Model(&def).Related(&packs, "AffectedPacks")
		defs[i].AffectedPacks = packs

		refs := []models.Reference{}
		//TODO error
		db.Model(&def).Related(&refs, "References")
		defs[i].References = refs
	}

	return defs, nil
}
