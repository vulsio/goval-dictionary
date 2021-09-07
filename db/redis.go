package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

/**
# Redis Data Structure

- Strings
  ┌───┬──────────────────────────────────────┬───────────┬──────────────────────────────────────────────────┐
  │NO │                   KEY                │   VALUE   │                   PURPOSE                        │
  └───┴──────────────────────────────────────┴───────────┴──────────────────────────────────────────────────┘
  ┌───┬──────────────────────────────────────┬───────────┬──────────────────────────────────────────────────┐
  │ 1 │ OVAL#$OSFAMILY#$VERSION#DEP          │   JSON    │ TO DELETE OUTDATED AND UNNEEDED FIELD AND MEMBER │
  ├───┼──────────────────────────────────────┼───────────┼──────────────────────────────────────────────────┤
  │ 2 │ OVAL#$OSFAMILY#$VERSION#LASTMODIFIED │ time.TIME │ TO GET Last Modified                             │
  └───┴──────────────────────────────────────┴───────────┴──────────────────────────────────────────────────┘

- Sets
  ┌───┬────────────────────────────────────────────────┬───────────────┬──────────────────────────────────────────┐
  │NO │ KEY                                            │     MEMBER    │ PURPOSE                                  │
  └───┴────────────────────────────────────────────────┴───────────────┴──────────────────────────────────────────┘
  ┌───┬────────────────────────────────────────────────┬───────────────┬──────────────────────────────────────────┐
  │ 1 │ OVAL#$OSFAMILY#$VERSION#PKG#$PACKAGENAME       │ $DEFINITIONID │ TO GET []$DEFINITIONID                   │
  ├───┼────────────────────────────────────────────────┼───────────────┼──────────────────────────────────────────┤
  │ 2 │ OVAL#$OSFAMILY#$VERSION#PKG#$PACKAGENAME#$ARCH │ $DEFINITIONID │ TO GET []$DEFINITIONID for Amazon/Oracle │
  ├───┼────────────────────────────────────────────────┼───────────────┼──────────────────────────────────────────┤
  │ 3 │ OVAL#$OSFAMILY#$VERSION#CVE#$CVEID             │ $DEFINITIONID │ TO GET []$DEFINITIONID                   │
  └───┴────────────────────────────────────────────────┴───────────────┴──────────────────────────────────────────┘

- Hash
  ┌───┬─────────────────────────────┬───────────────┬───────────┬─────────────────────────────────────────┐
  │NO │         KEY                 │     FIELD     │   VALUE   │                PURPOSE                  │
  └───┴─────────────────────────────┴───────────────┴───────────┴─────────────────────────────────────────┘
  ┌───┬─────────────────────────────┬───────────────┬───────────┬─────────────────────────────────────────┐
  │ 1 │ OVAL#$OSFAMILY#$VERSION#DEF │ $DEFINITIONID │ $OVALJSON │ TO GET OVALJSON                         │
  ├───┼─────────────────────────────┼───────────────┼───────────┼─────────────────────────────────────────┤
  │ 2 │ OVAL#FETCHMETA              │   Revision    │   string  │ GET Go-Oval-Disctionary Binary Revision │
  ├───┼─────────────────────────────┼───────────────┼───────────┼─────────────────────────────────────────┤
  │ 3 │ OVAL#FETCHMETA              │ SchemaVersion │    uint   │ GET Go-Oval-Disctionary Schema Version  │
  └───┴─────────────────────────────┴───────────────┴───────────┴─────────────────────────────────────────┘

  **/

// Supported DB dialects.
const (
	dialectRedis          = "redis"
	defKeyFormat          = "OVAL#%s#%s#DEF"
	cveKeyFormat          = "OVAL#%s#%s#CVE#%s"
	pkgKeyFormat          = "OVAL#%s#%s#PKG#%s"
	depKeyFormat          = "OVAL#%s#%s#DEP"
	lastModifiedKeyFormat = "OVAL#%s#%s#LASTMODIFIED"
	fetchMetaKey          = "OVAL#FETCHMETA"
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
			return nil, false, err
		}
	}

	if err = driver.OpenDB(dbType, dbpath, debugSQL); err != nil {
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

	return driver, false, nil
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
	ctx := context.Background()
	if err = d.conn.Ping(ctx).Err(); err != nil {
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
	case c.Amazon:
		osVer = getAmazonLinux1or2(osVer)
	case c.Alpine, c.OpenSUSE, c.OpenSUSE + ".nonfree", c.OpenSUSELeap, c.OpenSUSELeap + ".nonfree":
	default:
		osVer = major(osVer)
	}

	ctx := context.Background()
	key := fmt.Sprintf(pkgKeyFormat, family, osVer, packName)
	pkgKeys := []string{}
	switch family {
	case c.Amazon, c.Oracle:
		// affected packages for Amazon and Oracle OVAL needs to consider arch
		if arch != "" {
			pkgKeys = append(pkgKeys, fmt.Sprintf("%s#%s", key, arch))
		} else {
			dbsize, err := d.conn.DBSize(ctx).Result()
			if err != nil {
				return nil, fmt.Errorf("Failed to DBSize. err: %s", err)
			}

			var cursor uint64
			for {
				var keys []string
				var err error
				keys, cursor, err = d.conn.Scan(ctx, cursor, fmt.Sprintf("%s#%s", key, "*"), dbsize/5).Result()
				if err != nil {
					return nil, fmt.Errorf("Failed to Scan. err: %s", err)
				}

				pkgKeys = append(pkgKeys, keys...)

				if cursor == 0 {
					break
				}
			}
		}
	default:
		pkgKeys = append(pkgKeys, key)
	}

	pipe := d.conn.Pipeline()
	for _, pkey := range pkgKeys {
		_ = pipe.SMembers(ctx, pkey)
	}
	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	defIDs := []string{}
	for _, cmder := range cmders {
		result, err := cmder.(*redis.StringSliceCmd).Result()
		if err != nil {
			return nil, fmt.Errorf("Failed to SMembers. err: %s", err)
		}

		defIDs = append(defIDs, result...)
	}

	defStrs, err := d.conn.HMGet(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defIDs...).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HMGet. err: %s", err)
	}

	defs := []models.Definition{}
	for _, defstr := range defStrs {
		def, err := restoreDefinition(defstr.(string), family, osVer, arch)
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
	case c.Amazon:
		osVer = getAmazonLinux1or2(osVer)
	case c.Alpine, c.OpenSUSE, c.OpenSUSE + ".nonfree", c.OpenSUSELeap, c.OpenSUSELeap + ".nonfree":
	default:
		osVer = major(osVer)
	}

	ctx := context.Background()
	defIDs, err := d.conn.SMembers(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, cveID)).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to SMembers. err: %s", err)
	}

	defStrs, err := d.conn.HMGet(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defIDs...).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HMGet. err: %s", err)
	}

	defs := []models.Definition{}
	for _, defstr := range defStrs {
		def, err := restoreDefinition(defstr.(string), family, osVer, arch)
		if err != nil {
			return nil, fmt.Errorf("Failed to restoreDefinition. err: %s", err)
		}
		defs = append(defs, def)
	}

	return defs, nil
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
	ctx := context.Background()
	expire := viper.GetUint("expire")

	// newDeps, oldDeps: {"DEFID": {"cves": {"CVEID": {}}, "packages": {"PACKNAME": {}}}}
	newDeps := map[string]map[string]map[string]struct{}{}
	depKey := fmt.Sprintf(depKeyFormat, root.Family, root.OSVersion)
	oldDepsStr, err := d.conn.Get(ctx, depKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return fmt.Errorf("Failed to Get key: %s. err: %s", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return fmt.Errorf("Failed to unmarshal JSON. err: %s", err)
	}

	bar := pb.StartNew(len(root.Definitions))
	for chunked := range chunkSlice(root.Definitions, 10) {
		pipe := d.conn.Pipeline()
		defKey := fmt.Sprintf(defKeyFormat, root.Family, root.OSVersion)
		for _, def := range chunked {
			var dj []byte
			if dj, err = json.Marshal(def); err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			if err := pipe.HSet(ctx, defKey, def.DefinitionID, string(dj)).Err(); err != nil {
				return fmt.Errorf("Failed to HSet. err: %s", err)
			}
			if _, ok := newDeps[def.DefinitionID]; !ok {
				newDeps[def.DefinitionID] = map[string]map[string]struct{}{"cves": {}, "packages": {}}
			}

			for _, cve := range def.Advisory.Cves {
				cveKey := fmt.Sprintf(cveKeyFormat, root.Family, root.OSVersion, cve.CveID)
				if err := pipe.SAdd(ctx, cveKey, def.DefinitionID).Err(); err != nil {
					return fmt.Errorf("Failed to SAdd CVE-ID. err: %s", err)
				}
				if expire > 0 {
					if err := pipe.Expire(ctx, cveKey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
						return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
					}
				} else {
					if err := pipe.Persist(ctx, cveKey).Err(); err != nil {
						return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
					}
				}

				newDeps[def.DefinitionID]["cves"][cve.CveID] = struct{}{}
				if _, ok := oldDeps[def.DefinitionID]["cves"]; ok {
					delete(oldDeps[def.DefinitionID]["cves"], cve.CveID)
					if len(oldDeps[def.DefinitionID]["cves"]) == 0 {
						delete(oldDeps[def.DefinitionID], "cves")
					}
				}
			}

			for _, pack := range def.AffectedPacks {
				pkgName := pack.Name
				switch family {
				case c.Amazon, c.Oracle:
					// affected packages for Amazon OVAL needs to consider arch
					pkgName = fmt.Sprintf("%s#%s", pkgName, pack.Arch)
				}
				pkgKey := fmt.Sprintf(pkgKeyFormat, root.Family, root.OSVersion, pkgName)

				if err := pipe.SAdd(ctx, pkgKey, def.DefinitionID).Err(); err != nil {
					return fmt.Errorf("Failed to SAdd Package. err: %s", err)
				}
				if expire > 0 {
					if err := pipe.Expire(ctx, pkgKey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
						return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
					}
				} else {
					if err := pipe.Persist(ctx, pkgKey).Err(); err != nil {
						return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
					}
				}

				newDeps[def.DefinitionID]["packages"][pkgName] = struct{}{}
				if _, ok := oldDeps[def.DefinitionID]["packages"]; ok {
					delete(oldDeps[def.DefinitionID]["packages"], pkgName)
					if len(oldDeps[def.DefinitionID]["packages"]) == 0 {
						delete(oldDeps[def.DefinitionID], "packages")
					}
				}
			}

			if len(oldDeps[def.DefinitionID]) == 0 {
				delete(oldDeps, def.DefinitionID)
			}
		}
		if expire > 0 {
			if err := pipe.Expire(ctx, defKey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
				return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
			}
		} else {
			if err := pipe.Persist(ctx, defKey).Err(); err != nil {
				return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
			}
		}
		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(10)
	}
	bar.Finish()

	pipe := d.conn.Pipeline()
	for defID, definitions := range oldDeps {
		for cveID := range definitions["cves"] {
			if err := pipe.SRem(ctx, fmt.Sprintf(cveKeyFormat, root.Family, root.OSVersion, cveID), defID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		for pack := range definitions["packages"] {
			if err := pipe.SRem(ctx, fmt.Sprintf(cveKeyFormat, root.Family, root.OSVersion, pack), defID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		if err := pipe.HDel(ctx, fmt.Sprintf(defKeyFormat, root.Family, root.OSVersion), defID).Err(); err != nil {
			return fmt.Errorf("Failed to HDel. err: %s", err)
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return fmt.Errorf("Failed to Marshal JSON. err: %s", err)
	}
	if err := pipe.Set(ctx, depKey, string(newDepsJSON), time.Duration(expire*uint(time.Second))).Err(); err != nil {
		return fmt.Errorf("Failed to Set depkey. err: %s", err)
	}
	if err := pipe.Set(ctx, fmt.Sprintf(lastModifiedKeyFormat, root.Family, root.OSVersion), root.Timestamp, time.Duration(expire*uint(time.Second))).Err(); err != nil {
		return fmt.Errorf("Failed to Set LastModifiedKey. err: %s", err)
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
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
	switch family {
	case c.CentOS:
		family = c.RedHat
	case c.Raspbian:
		family = c.Debian
	case c.Amazon:
		osVer = getAmazonLinux1or2(osVer)
	case c.Alpine, c.OpenSUSE, c.OpenSUSE + ".nonfree", c.OpenSUSELeap, c.OpenSUSELeap + ".nonfree":
	default:
		osVer = major(osVer)
	}

	count, err := d.conn.HLen(context.Background(), fmt.Sprintf(defKeyFormat, family, osVer)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return 0, fmt.Errorf("Failed to HLen. err: %s", err)
		}
		return 0, nil
	}

	return int(count), nil
}

// GetLastModified get last modified time of OVAL in roots
func (d *RedisDriver) GetLastModified(osFamily, osVer string) (time.Time, error) {
	switch osFamily {
	case c.CentOS:
		osFamily = c.RedHat
	case c.Raspbian:
		osFamily = c.Debian
	case c.Amazon:
		osVer = getAmazonLinux1or2(osVer)
	case c.Alpine, c.OpenSUSE, c.OpenSUSE + ".nonfree", c.OpenSUSELeap, c.OpenSUSELeap + ".nonfree":
	default:
		osVer = major(osVer)
	}

	lastModifiedStr, err := d.conn.Get(context.Background(), fmt.Sprintf(lastModifiedKeyFormat, osFamily, osVer)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return time.Time{}, fmt.Errorf("Failed to Get. err: %s", err)
		}
		return time.Now().AddDate(-100, 0, 0), nil
	}

	lastModified, err := time.Parse("2006-01-02T15:04:05+09:00", lastModifiedStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("Failed to parse LastModified. err: %s", err)
	}
	return lastModified, nil
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
func (d *RedisDriver) IsGovalDictModelV1() (bool, error) {
	ctx := context.Background()

	exists, err := d.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return false, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		keys, _, err := d.conn.Scan(ctx, 0, "OVAL#*", 1).Result()
		if err != nil {
			return false, fmt.Errorf("Failed to Scan. err: %s", err)
		}
		if len(keys) == 0 {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

// GetFetchMeta get FetchMeta from Database
func (d *RedisDriver) GetFetchMeta() (*models.FetchMeta, error) {
	ctx := context.Background()

	exists, err := d.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GovalDictRevision: c.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	revision, err := d.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGet Revision. err: %s", err)
	}

	verstr, err := d.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGet SchemaVersion. err: %s", err)
	}
	version, err := strconv.ParseUint(verstr, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("Failed to ParseUint. err: %s", err)
	}

	return &models.FetchMeta{GovalDictRevision: revision, SchemaVersion: uint(version)}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (d *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return d.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": fetchMeta.GovalDictRevision, "SchemaVersion": fetchMeta.SchemaVersion}).Err()
}
