package db

import (
	"strings"
	"time"

	"golang.org/x/xerrors"

	c "github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/models"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool, Option) error
	CloseDB() error
	MigrateDB() error

	IsGovalDictModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	GetByPackName(family string, osVer string, packName string, arch string) ([]models.Definition, error)
	GetByCveID(family string, osVer string, cveID string, arch string) ([]models.Definition, error)
	InsertOval(*models.Root) error
	CountDefs(string, string) (int, error)
	GetLastModified(string, string) (time.Time, error)
}

// Option :
type Option struct {
	RedisTimeout time.Duration
}

// NewDB return DB accessor.
func NewDB(dbType, dbPath string, debugSQL bool, option Option) (driver DB, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, xerrors.Errorf("Failed to new db. err: %w", err)
	}

	if err := driver.OpenDB(dbType, dbPath, debugSQL, option); err != nil {
		return nil, xerrors.Errorf("Failed to open db. err: %w", err)
	}

	isV1, err := driver.IsGovalDictModelV1()
	if err != nil {
		return nil, xerrors.Errorf("Failed to IsGovalDictModelV1. err: %w", err)
	}
	if isV1 {
		return nil, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		return driver, xerrors.Errorf("Failed to migrate db. err: %w", err)
	}
	return driver, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, xerrors.Errorf("Invalid database dialect. dbType: %s", dbType)
}

func formatFamilyAndOSVer(family, osVer string) (string, string, error) {
	switch family {
	case c.Debian:
		return family, major(osVer), nil
	case c.Ubuntu:
		return family, majorDotMinor(osVer), nil
	case c.Raspbian:
		return c.Debian, major(osVer), nil
	case c.RedHat:
		return family, major(osVer), nil
	case c.CentOS:
		return c.RedHat, major(osVer), nil
	case c.Oracle:
		return family, major(osVer), nil
	case c.Amazon:
		osVer, err := getAmazonLinuxVer(osVer)
		if err != nil {
			return "", "", xerrors.Errorf("Failed to detect amazon version. err: %w", err)
		}
		return family, osVer, nil
	case c.Alpine:
		return family, majorDotMinor(osVer), nil
	case c.Fedora:
		return family, major(osVer), nil
	case c.OpenSUSE:
		if osVer != "tumbleweed" {
			return family, majorDotMinor(osVer), nil
		}
		return family, osVer, nil
	case c.OpenSUSELeap, c.SUSEEnterpriseDesktop, c.SUSEEnterpriseServer:
		return family, majorDotMinor(osVer), nil
	default:
		return "", "", xerrors.Errorf("Failed to detect family. err: unknown os family(%s)", family)
	}
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

// getAmazonLinuxVer returns AmazonLinux 1, 2, 2022, 2023
func getAmazonLinuxVer(osVersion string) (string, error) {
	switch s := strings.Fields(osVersion)[0]; s {
	case "1", "2", "2022", "2023", "2025", "2027", "2029":
		return s, nil
	default:
		if _, err := time.Parse("2006.01", s); err == nil {
			return "1", nil
		}
		return "", xerrors.Errorf(`unexpected Amazon Linux 1 version format. expected: "yyyy.MM", actual: "%s"`, s)
	}
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
