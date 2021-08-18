package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/inconshreveable/log15"
	"github.com/kotakanbe/goval-dictionary/config"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

/**
# Redis Data Structure

- Strings
  ┌───┬───────────────────────────────────────────┬─────────────┬─────────────────┐
  │NO │                   KEY                     │    VALUE    │     PURPOSE     │
  └───┴───────────────────────────────────────────┴─────────────┴─────────────────┘
  ┌───┬───────────────────────────────────────────┬─────────────┬─────────────────┐
  │ 1 │ OVAL#$OSFAMILY#$VERSION#DEF#$DEFINITIONID │  $OVALJSON  │ TO GET OVALJSON │
  └───┴───────────────────────────────────────────┴─────────────┴─────────────────┘

- Sets
  ┌───┬────────────────────────────────────────────────┬───────────────────────────────────────────┬──────────────────────────────────────────┐
  │NO │ KEY                                            │ MEMBER                                    │ PURPOSE                                  │
  └───┴────────────────────────────────────────────────┴───────────────────────────────────────────┴──────────────────────────────────────────┘
  ┌───┬────────────────────────────────────────────────┬───────────────────────────────────────────┬──────────────────────────────────────────┐
  │ 2 │ OVAL#$OSFAMILY#$VERSION#PKG#$PACKAGENAME       │ OVAL#$OSFAMILY#$VERSION#DEF#$DEFINITIONID │ TO GET []$DEFINITIONID                   │
  └───┴────────────────────────────────────────────────┴───────────────────────────────────────────┴──────────────────────────────────────────┘
  ┌───┬────────────────────────────────────────────────┬───────────────────────────────────────────┬──────────────────────────────────────────┐
  │ 3 │ OVAL#$OSFAMILY#$VERSION#PKG#$PACKAGENAME#$ARCH │ OVAL#$OSFAMILY#$VERSION#DEF#$DEFINITIONID │ TO GET []$DEFINITIONID for Amazon/Oracle │
  └───┴────────────────────────────────────────────────┴───────────────────────────────────────────┴──────────────────────────────────────────┘
  ┌───┬────────────────────────────────────────────────┬───────────────────────────────────────────┬──────────────────────────────────────────┐
  │ 4 │ OVAL#$OSFAMILY#$VERSION#CVE#$CVEID             │ OVAL#$OSFAMILY#$VERSION#DEF#$DEFINITIONID │ TO GET []$DEFINITIONID                   │
  └───┴────────────────────────────────────────────────┴───────────────────────────────────────────┴──────────────────────────────────────────┘
**/

// Supported DB dialects.
const (
	dialectRedis = "redis"
	keyPrefix    = "OVAL#"
	keySeparator = "#"
)

// RedisDriver is Driver for Redis
type RedisDriver struct {
	name string
	conn *redis.Client
}

// NewRedis return Redis driver
func NewRedis(family, dbType, dbpath string, debugSQL bool) (driver *RedisDriver, locked bool, err error) {
	driver = &RedisDriver{
		name: dbType,
	}

	// when using server command, family is empty.
	if 0 < len(family) {
		if err = driver.NewOvalDB(family); err != nil {
			return
		}
	}

	if err = driver.OpenDB(dbType, dbpath, debugSQL); err != nil {
		return
	}

	return
}

// NewOvalDB create a OvalDB client
func (d *RedisDriver) NewOvalDB(family string) error {
	switch family {
	case c.CentOS, c.Debian, c.Ubuntu, c.RedHat, c.Oracle,
		c.OpenSUSE, c.OpenSUSELeap, c.SUSEOpenstackCloud,
		c.SUSEEnterpriseServer, c.SUSEEnterpriseDesktop, c.SUSEEnterpriseWorkstation,
		c.Alpine, c.Amazon:

	default:
		if strings.HasPrefix(family, c.OpenSUSE) ||
			strings.HasPrefix(family, c.OpenSUSELeap) ||
			strings.HasPrefix(family, c.SUSEEnterpriseServer) ||
			strings.HasPrefix(family, c.SUSEEnterpriseDesktop) ||
			strings.HasPrefix(family, c.SUSEEnterpriseModule) ||
			strings.HasPrefix(family, c.SUSEEnterpriseWorkstation) ||
			strings.HasPrefix(family, c.SUSEOpenstackCloud) {
			return nil
		}

		return fmt.Errorf("Unknown OS Type: %s", family)
	}
	return nil
}

// Name is driver name
func (d *RedisDriver) Name() string {
	return d.name
}

// OpenDB opens Database
func (d *RedisDriver) OpenDB(dbType, dbPath string, debugSQL bool) (err error) {
	var option *redis.Options
	if option, err = redis.ParseURL(dbPath); err != nil {
		log15.Error("Failed to parse url", "err", err)
		return fmt.Errorf("Failed to Parse Redis URL. dbpath: %s, err: %s", dbPath, err)
	}
	d.conn = redis.NewClient(option)
	if err = d.conn.Ping().Err(); err != nil {
		return fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
	}
	return nil
}

// CloseDB close Database
func (d *RedisDriver) CloseDB() (err error) {
	if d.conn == nil {
		return
	}
	if err = d.conn.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", d.name, err)
	}
	return
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName, arch
func (d *RedisDriver) GetByPackName(family, osVer, packName, arch string) ([]models.Definition, error) {
	switch family {
	case c.CentOS:
		family = c.RedHat
	case c.Raspbian:
		family = c.Debian
	}

	if family == c.Amazon {
		osVer = getAmazonLinux1or2(osVer)
	} else if family != c.Alpine {
		// OVAL is provided for each major for all other OSes except alpine,
		// But Alpine provides it for each major.minor
		osVer = major(osVer)
	}

	key := fmt.Sprintf("%s%s#%s#PKG#%s", keyPrefix, family, osVer, packName)
	defKeys := map[string]bool{}
	switch family {
	case c.Amazon, c.Oracle:
		// affected packages for Amazon and Oracle OVAL needs to consider arch
		if arch != "" {
			key = fmt.Sprintf("%s#%s", key, arch)
			keys, err := d.conn.SMembers(key).Result()
			if err != nil {
				return nil, fmt.Errorf("Failed to SMembers(%s). err: %s", key, err)
			}

			for _, k := range keys {
				defKeys[k] = true
			}
		} else {
			key = fmt.Sprintf("%s#%s", key, "*")
			keys, err := d.conn.Keys(key).Result()
			if err != nil {
				return nil, fmt.Errorf("Failed to Keys(%s). err: %s", key, err)
			}

			for _, k := range keys {
				dkeys, err := d.conn.SMembers(k).Result()
				if err != nil {
					return nil, fmt.Errorf("Failed to SMembers(%s). err: %s", key, err)
				}

				for _, dkey := range dkeys {
					if _, ok := defKeys[dkey]; !ok {
						defKeys[dkey] = true
					}
				}
			}
		}
	default:
		keys, err := d.conn.SMembers(key).Result()
		if err != nil {
			return nil, fmt.Errorf("Failed to SMembers(%s). err: %s", key, err)
		}

		for _, k := range keys {
			defKeys[k] = true
		}
	}

	defs := []models.Definition{}
	for defKey := range defKeys {
		defstr, err := d.conn.Get(defKey).Result()
		if err != nil {
			return nil, fmt.Errorf("Failed to GET(%s). err: %s", defKey, err)
		}
		if defstr == "" {
			return nil, fmt.Errorf("Failed to Get Definition ID. err: key(%s) does not exists", defKey)
		}

		_, version, _, err := splitDefKey(defKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to splitDefKey. err: %s", err)
		}
		def, err := restoreDefinition(defstr, family, version, arch)
		if err != nil {
			return nil, fmt.Errorf("Failed to restoreDefinition. err: %s", err)
		}
		defs = append(defs, def)
	}

	return defs, nil
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func (d *RedisDriver) GetByCveID(family, osVer, cveID, arch string) ([]models.Definition, error) {
	switch family {
	case c.CentOS:
		family = c.RedHat
	case c.Raspbian:
		family = c.Debian
	}

	if family == c.Amazon {
		osVer = getAmazonLinux1or2(osVer)
	} else if family != c.Alpine {
		// OVAL is provided for each major for all other OSes except alpine,
		// But Alpine provides it for each major.minor
		osVer = major(osVer)
	}

	key := fmt.Sprintf("%s%s#%s#CVE#%s", keyPrefix, family, osVer, cveID)
	defKeys, err := d.conn.SMembers(key).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to SMembers(%s). err: %s", key, err)
	}

	defs := []models.Definition{}
	for _, defKey := range defKeys {
		defstr, err := d.conn.Get(defKey).Result()
		if err != nil {
			return nil, fmt.Errorf("Failed to GET(%s). err: %s", defKey, err)
		}
		if defstr == "" {
			return nil, fmt.Errorf("Failed to Get Definition ID. err: key(%s) does not exists", defKey)
		}

		_, version, _, err := splitDefKey(defKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to splitDefKey. err: %s", err)
		}
		def, err := restoreDefinition(defstr, family, version, arch)
		if err != nil {
			return nil, fmt.Errorf("Failed to restoreDefinition. err: %s", err)
		}
		defs = append(defs, def)
	}

	return defs, nil
}

func splitDefKey(defkey string) (string, string, string, error) {
	ss := strings.Split(strings.TrimPrefix(defkey, keyPrefix), keySeparator)
	if len(ss) != 4 {
		return "", "", "", fmt.Errorf("Failed to parse defkey(%s) correctly", defkey)
	}

	return ss[0], ss[1], ss[3], nil
}

func restoreDefinition(defstr, family, version, arch string) (models.Definition, error) {
	var def models.Definition
	if err := json.Unmarshal([]byte(defstr), &def); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return models.Definition{}, err
	}

	switch family {
	case c.Amazon, c.Oracle:
		def.AffectedPacks = fileterPacksByArch(def.AffectedPacks, arch)
	case c.RedHat:
		def.AffectedPacks = filterByRedHatMajor(def.AffectedPacks, version)
	}

	return def, nil
}

func fileterPacksByArch(packs []models.Package, arch string) []models.Package {
	if arch == "" {
		return packs
	}

	filtered := []models.Package{}
	for _, pack := range packs {
		if pack.Arch == arch {
			filtered = append(filtered, pack)
		}
	}

	return filtered
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

// InsertOval inserts OVAL
func (d *RedisDriver) InsertOval(family string, root *models.Root, meta models.FileMeta) (err error) {
	expire := viper.GetUint("expire")
	for chunked := range chunkSlice(root.Definitions, 10) {
		pipe := d.conn.Pipeline()
		for _, def := range chunked {
			var dj []byte
			if dj, err = json.Marshal(def); err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			defKey := fmt.Sprintf("%s%s#%s#DEF#%s", keyPrefix, root.Family, root.OSVersion, def.DefinitionID)
			if err := pipe.Set(defKey, dj, time.Duration(expire*uint(time.Second))).Err(); err != nil {
				return fmt.Errorf("Failed to SET definition id. err: %s", err)
			}

			for _, cve := range def.Advisory.Cves {
				key := fmt.Sprintf("%s%s#%s#CVE#%s", keyPrefix, root.Family, root.OSVersion, cve.CveID)
				if err := pipe.SAdd(key, defKey).Err(); err != nil {
					return fmt.Errorf("Failed to SAdd CVE-ID. err: %s", err)
				}
				if expire > 0 {
					if err := pipe.Expire(key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
						return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
					}
				} else {
					if err := pipe.Persist(key).Err(); err != nil {
						return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
					}
				}
			}

			for _, pack := range def.AffectedPacks {
				key := fmt.Sprintf("%s%s#%s#PKG#%s", keyPrefix, root.Family, root.OSVersion, pack.Name)
				switch family {
				case c.Amazon, c.Oracle:
					// affected packages for Amazon OVAL needs to consider arch
					key = fmt.Sprintf("%s#%s", key, pack.Arch)
				}
				if err := pipe.SAdd(key, defKey).Err(); err != nil {
					return fmt.Errorf("Failed to SAdd Package. err: %s", err)
				}
				if expire > 0 {
					if err := pipe.Expire(key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
						return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
					}
				} else {
					if err := pipe.Persist(key).Err(); err != nil {
						return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
					}
				}
			}
		}
		if _, err = pipe.Exec(); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	return nil
}

// InsertFileMeta inserts FileMeta
// Redis do not use this.
func (d *RedisDriver) InsertFileMeta(meta models.FileMeta) error {
	return nil
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func chunkSlice(l []models.Definition, n int) chan []models.Definition {
	ch := make(chan []models.Definition)

	go func() {
		for i := 0; i < len(l); i += n {
			fromIdx := i
			toIdx := i + n
			if toIdx > len(l) {
				toIdx = len(l)
			}
			ch <- l[fromIdx:toIdx]
		}
		close(ch)
	}()
	return ch
}

// CountDefs counts the number of definitions specified by args
func (d *RedisDriver) CountDefs(family, osVer string) (int, error) {
	// TODO not implemented yet
	return 1, nil
}

// GetLastModified get last modified time of OVAL in roots
func (d *RedisDriver) GetLastModified(osFamily, osVer string) (time.Time, error) {
	// TODO not implemented yet
	return time.Now(), nil
}

// getAmazonLinux2 returns AmazonLinux1 or 2
func getAmazonLinux1or2(osVersion string) string {
	ss := strings.Fields(osVersion)
	if ss[0] == "2" {
		return "2"
	}
	return "1"
}

// IsGovalDictModelV1 determines if the DB was created at the time of goval-dictionary Model v1
func (d *RedisDriver) IsGovalDictModelV1() bool {
	return false
}

// GetFetchMeta get FetchMeta from Database
func (d *RedisDriver) GetFetchMeta() (*models.FetchMeta, error) {
	return &models.FetchMeta{GovalDictRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (d *RedisDriver) UpsertFetchMeta(*models.FetchMeta) error {
	return nil
}
