package db

import (
	"fmt"
	"time"

	"github.com/kotakanbe/goval-dictionary/db/rdb"
	"github.com/kotakanbe/goval-dictionary/models"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	NewOvalDB(string) error
	CloseDB() error
	GetByPackName(string, string, string, string) ([]models.Definition, error)
	GetByCveID(string, string, string, string) ([]models.Definition, error)
	InsertOval(string, *models.Root, models.FetchMeta) error
	InsertFetchMeta(models.FetchMeta) error
	CountDefs(string, string) (int, error)
	GetLastModified(string, string) (time.Time, error)
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
