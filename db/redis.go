package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
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
  │   │                │             │$VERSION::$CVEID│  BY PACKAGENAME  │
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
	name   string
	conn   *redis.Client
	ovaldb string
}

// NewRedis return Redis driver
func NewRedis(family, dbType, dbpath string, debugSQL bool) (driver *RedisDriver, err error) {
	driver = &RedisDriver{
		name: dbType,
	}
	// when using server command, family is empty.
	if 0 < len(family) {
		if err = driver.NewOvalDB(family); err != nil {
			return
		}
	}

	log.Debugf("Opening DB (%s).", driver.Name())
	if err = driver.OpenDB(dbType, dbpath, debugSQL); err != nil {
		return
	}

	return
}

// NewOvalDB create a OvalDB client
func (d *RedisDriver) NewOvalDB(family string) error {
	switch family {
	case c.CentOS:
		d.ovaldb = c.RedHat
	case c.Debian, c.Ubuntu, c.RedHat, c.Oracle,
		c.OpenSUSE, c.OpenSUSELeap, c.SUSEEnterpriseServer,
		c.SUSEEnterpriseDesktop, c.SUSEOpenstackCloud,
		c.Alpine:

		d.ovaldb = family
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

// OvalDB is OvalDB name
func (d *RedisDriver) OvalDB() string {
	return d.ovaldb
}

// OpenDB opens Database
func (d *RedisDriver) OpenDB(dbType, dbPath string, debugSQL bool) (err error) {
	var option *redis.Options
	if option, err = redis.ParseURL(dbPath); err != nil {
		log.Error(err)
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
		log.Errorf("Failed to close DB. Type: %s. err: %s", d.name, err)
		return
	}
	return
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName
func (d *RedisDriver) GetByPackName(osVer, packName string) (defs []models.Definition, err error) {
	osVer = major(osVer)
	defs = []models.Definition{}
	var result *redis.StringSliceCmd
	if result = d.conn.ZRange(hashKeyPrefix+packName, 0, -1); result.Err() != nil {
		err = result.Err()
		log.Error(result.Err())
		return
	}

	encountered := map[string]bool{}
	for _, v := range result.Val() {
		keyWithoutPrefix := v[len(hashKeyPrefix):]
		keys := strings.Split(keyWithoutPrefix, hashKeySeparator)
		if keys[0] != d.OvalDB() || keys[1] != osVer {
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
func (d *RedisDriver) GetByCveID(osVer, cveID string) ([]models.Definition, error) {
	hashKey := getHashKey(d.OvalDB(), osVer, cveID)
	return getByHashKey(hashKey, d.conn)
}

// InsertOval inserts OVAL
func (d *RedisDriver) InsertOval(root *models.Root, meta models.FetchMeta) (err error) {
	for chunked := range chunkSlice(root.Definitions, 10) {
		var pipe redis.Pipeliner
		pipe = d.conn.Pipeline()
		for _, c := range chunked {
			var dj []byte
			if dj, err = json.Marshal(c); err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}
			for _, ref := range c.References {
				if ref.Source != "CVE" || ref.RefID == "" {
					continue
				}
				hashKey := getHashKey(root.Family, root.OSVersion, ref.RefID)
				if result := pipe.HSet(hashKey, c.DefinitionID, string(dj)); result.Err() != nil {
					return fmt.Errorf("Failed to HSet Definition. err: %s", result.Err())
				}
				for _, pack := range c.AffectedPacks {
					if result := pipe.ZAdd(hashKeyPrefix+pack.Name,
						redis.Z{Score: 0, Member: hashKey}); result.Err() != nil {
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
		log.Error(result.Err())
		return
	}

	for _, v := range result.Val() {
		var def models.Definition
		if err = json.Unmarshal([]byte(v), &def); err != nil {
			log.Errorf("Failed to Unmarshal json. err : %s", err)
			return
		}
		defs = append(defs, def)
	}
	return
}

func getHashKey(family, osVer, cveID string) string {
	return hashKeyPrefix + family + hashKeySeparator + osVer + hashKeySeparator + cveID
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
