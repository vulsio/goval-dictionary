package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
)

/**
# Redis Data Structure

- HASH
  ┌───┬────────────────┬─────────────┬────────────────┬──────────────────┐
  │NO │      HASH      │    FIELD    │     VALUE      │     PURPOSE      │
  └───┴────────────────┴─────────────┴────────────────┴──────────────────┘
  ┌───┬────────────────┬─────────────┬────────────────┬──────────────────┐
  │ 1 │OVAL#$OSFAMILY::│$DEFINITIONID│   $OVALJSON    │ TO GET OVALJSON  │
  │   │$VERSION::$CVEID│             │                │   BY CVEID&OS    │
  └───┴────────────────┴─────────────┴────────────────┴──────────────────┘

- ZINDEX
  ┌───┬────────────────┬─────────────┬────────────────┬──────────────────┐
  │NO │      KEY       │    SCORE    │     MEMBER     │     PURPOSE      │
  └───┴────────────────┴─────────────┴────────────────┴──────────────────┘
  ┌───┬────────────────┬─────────────┬────────────────┬──────────────────┐
  │ 2 │  $PACKAGENAME  │      0      │OVAL#$OSFAMILY::│TO GET []CVEID&OS │
  │   │      or        │             │$VERSION::$CVEID│  BY PACKAGENAME  │
  │   │  $PACKAGENAME::│             │                │                  │
  │   │  $ARCH         │             │                │For Amazon Linux  │
  └───┴────────────────┴─────────────┴────────────────┴──────────────────┘
**/

// Supported DB dialects.
const (
	dialectRedis     = "redis"
	hashKeyPrefix    = "OVAL#"
	hashKeySeparator = "::"
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

	log15.Debug("Opening DB.", "db", driver.Name())
	if err = driver.OpenDB(dbType, dbpath, debugSQL); err != nil {
		return
	}

	return
}

// NewOvalDB create a OvalDB client
func (d *RedisDriver) NewOvalDB(family string) error {
	switch family {
	case c.CentOS, c.Debian, c.Ubuntu, c.RedHat, c.Oracle,
		c.OpenSUSE, c.OpenSUSELeap, c.SUSEEnterpriseServer,
		c.SUSEEnterpriseDesktop, c.SUSEOpenstackCloud,
		c.Alpine, c.Amazon:

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
	if err = d.conn.Close(); err != nil {
		log15.Error("Failed to close DB.", "Type", d.name, "err", err)
		return
	}
	return
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName, arch
func (d *RedisDriver) GetByPackName(family, osVer, packName, arch string) (defs []models.Definition, err error) {
	if family == c.CentOS {
		family = c.RedHat
	}

	// Alpne provides vulnerability file for each major.minor
	if family != c.Alpine {
		if family == c.Amazon {
			osVer = getAmazonLinux1or2(osVer)
		} else {
			osVer = major(osVer)
		}
	}
	defs = []models.Definition{}
	var result *redis.StringSliceCmd

	zkey := hashKeyPrefix + packName
	if family == c.Amazon {
		// affected packages for Amazon OVAL needs to consider arch
		zkey = hashKeyPrefix + packName + hashKeySeparator + arch
	}

	if result = d.conn.ZRange(zkey, 0, -1); result.Err() != nil {
		err = result.Err()
		log15.Error("Failed to get definition from package", "err", result.Err())
		return
	}

	encountered := map[string]bool{}
	for _, v := range result.Val() {
		f, ver, _ := splitHashKey(v)
		if f != family || ver != osVer {
			continue
		}
		var tmpdefs []models.Definition
		if tmpdefs, err = getByHashKey(v, d.conn); err != nil {
			return nil, err
		}
		for _, vv := range tmpdefs {
			if !encountered[vv.DefinitionID] {
				encountered[vv.DefinitionID] = true
				defs = append(defs, vv)
			}
		}
	}
	return
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func (d *RedisDriver) GetByCveID(family, osVer, cveID string) ([]models.Definition, error) {
	hashKey := getHashKey(family, osVer, cveID)
	return getByHashKey(hashKey, d.conn)
}

// InsertOval inserts OVAL
func (d *RedisDriver) InsertOval(family string, root *models.Root, meta models.FetchMeta) (err error) {
	definitions := aggregateAffectedPackages(root.Definitions)
	for chunked := range chunkSlice(definitions, 10) {
		var pipe redis.Pipeliner
		pipe = d.conn.Pipeline()
		for _, def := range chunked {
			var dj []byte
			if dj, err = json.Marshal(def); err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}
			cveIDs := map[string]bool{}
			for _, ref := range def.References {
				if ref.Source != "CVE" || ref.RefID == "" {
					continue
				}
				cveIDs[ref.RefID] = true
			}
			for _, cve := range def.Advisory.Cves {
				cveIDs[cve.CveID] = true
			}
			for cveID := range cveIDs {
				hashKey := getHashKey(root.Family, root.OSVersion, cveID)
				if result := pipe.HSet(hashKey, def.DefinitionID, string(dj)); result.Err() != nil {
					return fmt.Errorf("Failed to HSet Definition. err: %s", result.Err())
				}
				for _, pack := range def.AffectedPacks {
					zkey := hashKeyPrefix + pack.Name
					if family == c.Amazon {
						// affected packages for Amazon OVAL needs to consider arch
						zkey = hashKeyPrefix + pack.Name + hashKeySeparator + pack.Arch
					}
					if result := pipe.ZAdd(
						zkey,
						redis.Z{
							Score:  0,
							Member: hashKey,
						}); result.Err() != nil {
						return fmt.Errorf("Failed to ZAdd package. err: %s", result.Err())
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

// InsertFetchMeta inserts FetchMeta
// Redis do not use this.
func (d *RedisDriver) InsertFetchMeta(meta models.FetchMeta) error {
	return nil
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func aggregateAffectedPackages(rootDefinitions []models.Definition) []models.Definition {
	defMap := map[string]models.Definition{}
	for _, def := range rootDefinitions {
		if d, ok := defMap[def.DefinitionID]; ok {
			d.AffectedPacks = append(d.AffectedPacks, def.AffectedPacks...)
			defMap[def.DefinitionID] = d
			continue
		}
		defMap[def.DefinitionID] = def
	}
	definitions := []models.Definition{}
	for _, def := range defMap {
		definitions = append(definitions, def)
	}
	return definitions
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

func getByHashKey(hashKey string, driver *redis.Client) (defs []models.Definition, err error) {
	defs = []models.Definition{}
	var result *redis.StringStringMapCmd
	if result = driver.HGetAll(hashKey); result.Err() != nil {
		err = result.Err()
		log15.Error("Failed to get definition.", "err", result.Err())
		return
	}

	for _, v := range result.Val() {
		var def models.Definition
		if err = json.Unmarshal([]byte(v), &def); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return
		}
		osFamily, osVer, _ := splitHashKey(hashKey)
		if osFamily == c.RedHat {
			def.AffectedPacks = filterByRedHatMajor(def.AffectedPacks, osVer)
		}
		defs = append(defs, def)
	}
	return
}

func getHashKey(family, osVer, cveID string) string {
	return hashKeyPrefix + family + hashKeySeparator + osVer + hashKeySeparator + cveID
}

func splitHashKey(hashKey string) (osFamily, osVer, cveID string) {
	keyWithoutPrefix := hashKey[len(hashKeyPrefix):]
	keys := strings.Split(keyWithoutPrefix, hashKeySeparator)
	if len(keys) != 3 {
		return "", "", ""
	}
	return keys[0], keys[1], keys[2]
}

// CountDefs counts the number of definitions specified by args
func (d *RedisDriver) CountDefs(family, osVer string) (int, error) {
	// TODO not implemented yet
	return 1, nil
}

// GetLastModified get last modified time of OVAL in roots
func (d *RedisDriver) GetLastModified(osFamily, osVer string) time.Time {
	// TODO not implemented yet
	return time.Now()
}

func filterByRedHatMajor(packs []models.Package, majorVer string) (filtered []models.Package) {
	for _, p := range packs {
		if strings.Contains(p.Version, ".el"+majorVer) {
			filtered = append(filtered, p)
		}
	}
	return
}

// getAmazonLinux2 returns AmazonLinux1 or 2
func getAmazonLinux1or2(osVersion string) string {
	ss := strings.Fields(osVersion)
	if ss[0] == "2" {
		return "2"
	}
	return "1"
}
