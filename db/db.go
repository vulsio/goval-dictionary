package db

import (
	"fmt"

	"github.com/kotakanbe/goval-dictionary/db/rdb"
	"github.com/kotakanbe/goval-dictionary/models"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	NewOvalDB(string) error
	OpenDB(string, string, bool) error
	MigrateDB() error
	GetByPackName(string, string) ([]models.Definition, error)
	GetByCveID(string, string) ([]models.Definition, error)
	InsertOval(*models.Root, models.FetchMeta) error
	InsertFetchMeta(models.FetchMeta) error
}

// NewDB return DB accessor.
func NewDB(dbType, ovalFamily string) (db DB, err error) {
	switch dbType {
	case rdb.DialectSqlite3, rdb.DialectMysql, rdb.DialectPostgreSQL:
		return rdb.NewRDB(dbType, ovalFamily)
	case dialectRedis:
		return NewRedis(dbType, ovalFamily)
	}
	return nil, fmt.Errorf("Invalid database dialect, %s", dbType)
}
