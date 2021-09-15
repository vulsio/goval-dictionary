package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	"golang.org/x/xerrors"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool) (bool, error)
	CloseDB() error
	MigrateDB() error

	IsGovalDictModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	GetByPackName(family string, osVer string, packName string, arch string) ([]models.Definition, error)
	GetByCveID(family string, osVer string, cveID string, arch string) ([]models.Definition, error)
	InsertOval(*models.Root, models.FileMeta) error
	InsertFileMeta(models.FileMeta) error
	CountDefs(string, string) (int, error)
	GetLastModified(string, string) (time.Time, error)
}

// NewDB return DB accessor.
func NewDB(dbType, dbPath string, debugSQL bool) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		log15.Error("Failed to new db.", "err", err)
		return driver, false, err
	}

	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL); err != nil {
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}

	isV1, err := driver.IsGovalDictModelV1()
	if err != nil {
		log15.Error("Failed to IsGovalDictModelV1.", "err", err)
		return nil, false, err
	}
	if isV1 {
		log15.Error("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again")
		return nil, false, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		log15.Error("Failed to migrate db.", "err", err)
		return driver, false, err
	}
	return driver, false, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect. err: %s", dbType)
}

func formatFamilyAndOSVer(family, osVer string) (string, string, error) {
	switch family {
	case c.Debian:
		osVer = major(osVer)
	case c.Ubuntu:
		osVer = major(osVer)
	case c.Raspbian:
		family = c.Debian
		osVer = major(osVer)
	case c.RedHat:
		osVer = major(osVer)
	case c.CentOS:
		family = c.RedHat
		osVer = major(osVer)
	case c.Oracle:
		osVer = major(osVer)
	case c.Amazon:
		osVer = getAmazonLinux1or2(osVer)
	case c.Alpine:
		osVer = majorDotMinor(osVer)
	default:
		if strings.Contains(family, "suse") {
			return family, majorDotMinor(osVer), nil
		}
		return "", "", fmt.Errorf("Failed to detect family. err: unknown os family(%s)", family)
	}

	return family, osVer, nil
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

// IndexChunk has a starting point and an ending point for Chunk
type IndexChunk struct {
	From, To int
}

func chunkSlice(length int, chunkSize int) <-chan IndexChunk {
	ch := make(chan IndexChunk)

	go func() {
		defer close(ch)

		for i := 0; i < length; i += chunkSize {
			idx := IndexChunk{i, i + chunkSize}
			if length < idx.To {
				idx.To = length
			}
			ch <- idx
		}
	}()

	return ch
}

func filterByRedHatMajor(packs []models.Package, majorVer string) (filtered []models.Package) {
	for _, p := range packs {
		if strings.Contains(p.Version, ".el"+majorVer) ||
			strings.Contains(p.Version, ".module+el"+majorVer) {
			filtered = append(filtered, p)
		}
	}
	return
}
