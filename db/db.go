package db

import (
	"fmt"
	"time"

	"github.com/vulsio/goval-dictionary/db/rdb"
	"github.com/vulsio/goval-dictionary/models"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	NewOvalDB(string) error
	CloseDB() error
	GetByPackName(family string, osVer string, packName string, arch string) ([]models.Definition, error)
	GetByCveID(family string, osVer string, cveID string, arch string) ([]models.Definition, error)
	InsertOval(string, *models.Root, models.FileMeta) error
	InsertFileMeta(models.FileMeta) error
	CountDefs(string, string) (int, error)
	GetLastModified(string, string) (time.Time, error)

	IsGovalDictModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error
}

// NewDB return DB accessor.
func NewDB(family, dbType, dbpath string, debugSQL bool) (db DB, locked bool, err error) {
	switch dbType {
	case rdb.DialectSqlite3, rdb.DialectMysql, rdb.DialectPostgreSQL:
		return rdb.NewRDB(family, dbType, dbpath, debugSQL)
	case dialectRedis:
		return NewRedis(family, dbType, dbpath, debugSQL)
	}
	return nil, false, fmt.Errorf("Invalid database dialect, %s", dbType)
}
