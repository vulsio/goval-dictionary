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
	GetByPackName(string, string) ([]models.Definition, error)
	GetByCveID(string, string) ([]models.Definition, error)
	InsertOval(*models.Root, models.FetchMeta) error
	InsertFetchMeta(models.FetchMeta) error
	CountDefs(string, string) (int, error)
	GetLastModified(string, string) time.Time
}

// NewDB return DB accessor.
func NewDB(family, dbType, dbpath string, debugSQL bool) (db DB, err error) {
	switch dbType {
	case rdb.DialectSqlite3, rdb.DialectMysql, rdb.DialectPostgreSQL:
		return rdb.NewRDB(family, dbType, dbpath, debugSQL)
	case dialectRedis:
		return NewRedis(family, dbType, dbpath, debugSQL)
	}
	return nil, fmt.Errorf("Invalid database dialect, %s", dbType)
}
