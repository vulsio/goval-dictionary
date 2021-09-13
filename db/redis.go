package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

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
  ┌───┬──────────────────────────────────────┬─────────┬──────────────────────────────────────────────────┐
  │NO │                   KEY                │  VALUE  │                   PURPOSE                        │
  └───┴──────────────────────────────────────┴─────────┴──────────────────────────────────────────────────┘
  ┌───┬──────────────────────────────────────┬─────────┬──────────────────────────────────────────────────┐
  │ 1 │ OVAL#$OSFAMILY#$VERSION#DEP          │   JSON  │ TO DELETE OUTDATED AND UNNEEDED FIELD AND MEMBER │
  ├───┼──────────────────────────────────────┼─────────┼──────────────────────────────────────────────────┤
  │ 2 │ OVAL#$OSFAMILY#$VERSION#LASTMODIFIED │  string │ TO GET Last Modified                             │
  └───┴──────────────────────────────────────┴─────────┴──────────────────────────────────────────────────┘

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
  │NO │               KEY           │     FIELD     │   VALUE   │                PURPOSE                  │
  └───┴─────────────────────────────┴───────────────┴───────────┴─────────────────────────────────────────┘
  ┌───┬─────────────────────────────┬───────────────┬───────────┬─────────────────────────────────────────┐
  │ 1 │ OVAL#$OSFAMILY#$VERSION#DEF │ $DEFINITIONID │ $OVALJSON │ TO GET OVALJSON                         │
  ├───┼─────────────────────────────┼───────────────┼───────────┼─────────────────────────────────────────┤
  │ 3 │ OVAL#FILEMETA               │   $FILENAME   │   string  │ GET Fetched OVAL Update Time            │
  ├───┼─────────────────────────────┼───────────────┼───────────┼─────────────────────────────────────────┤
  │ 4 │ OVAL#FETCHMETA              │   Revision    │   string  │ GET Go-Oval-Disctionary Binary Revision │
  ├───┼─────────────────────────────┼───────────────┼───────────┼─────────────────────────────────────────┤
  │ 5 │ OVAL#FETCHMETA              │ SchemaVersion │    uint   │ GET Go-Oval-Disctionary Schema Version  │
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
	fileMetaKey           = "OVAL#FILEMETA"
	fetchMetaKey          = "OVAL#FETCHMETA"
)

// RedisDriver is Driver for Redis
type RedisDriver struct {
	name string
	conn *redis.Client
}

// Name is driver name
func (r *RedisDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RedisDriver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	if err = r.connectRedis(dbPath); err != nil {
		err = fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
	}
	return
}

func (r *RedisDriver) connectRedis(dbPath string) error {
	var err error
	var option *redis.Options
	if option, err = redis.ParseURL(dbPath); err != nil {
		log15.Error("Failed to parse url.", "err", err)
		return err
	}
	r.conn = redis.NewClient(option)
	err = r.conn.Ping(context.Background()).Err()
	return err
}

// CloseDB close Database
func (r *RedisDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}
	if err = r.conn.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RedisDriver) MigrateDB() error {
	return nil
}

// GetByPackName select OVAL definition related to OS Family, osVer, packName, arch
func (r *RedisDriver) GetByPackName(family, osVer, packName, arch string) ([]models.Definition, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return nil, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
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
			dbsize, err := r.conn.DBSize(ctx).Result()
			if err != nil {
				return nil, fmt.Errorf("Failed to DBSize. err: %s", err)
			}

			var cursor uint64
			for {
				var keys []string
				var err error
				keys, cursor, err = r.conn.Scan(ctx, cursor, fmt.Sprintf("%s#%s", key, "*"), dbsize/5).Result()
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

	pipe := r.conn.Pipeline()
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
	if len(defIDs) == 0 {
		return []models.Definition{}, nil
	}

	defStrs, err := r.conn.HMGet(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defIDs...).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HMGet. err: %s", err)
	}

	defs := []models.Definition{}
	for _, defstr := range defStrs {
		if defstr == nil {
			return nil, fmt.Errorf("Failed to HMGet. err: Some fields do not exist. defIDs: %q", defIDs)
		}

		def, err := restoreDefinition(defstr.(string), family, osVer, arch)
		if err != nil {
			return nil, fmt.Errorf("Failed to restoreDefinition. err: %s", err)
		}
		defs = append(defs, def)
	}

	return defs, nil
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func (r *RedisDriver) GetByCveID(family, osVer, cveID, arch string) ([]models.Definition, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return nil, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	ctx := context.Background()
	defIDs, err := r.conn.SMembers(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, cveID)).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to SMembers. err: %s", err)
	}
	if len(defIDs) == 0 {
		return []models.Definition{}, nil
	}

	defStrs, err := r.conn.HMGet(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defIDs...).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HMGet. err: %s", err)
	}

	defs := []models.Definition{}
	for _, defstr := range defStrs {
		if defstr == nil {
			return nil, fmt.Errorf("Failed to HMGet. err: Some fields do not exist. defIDs: %q", defIDs)
		}

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

// InsertOval inserts OVAL
func (r *RedisDriver) InsertOval(root *models.Root, meta models.FileMeta) (err error) {
	ctx := context.Background()
	expire := viper.GetUint("expire")

	family, osVer, err := formatFamilyAndOSVer(root.Family, root.OSVersion)
	if err != nil {
		return fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	oldFileMeta, err := r.GetFileMeta(meta)
	if err != nil {
		return fmt.Errorf("Failed to GetFileMeta. err: %s", err)
	}
	if meta.Timestamp.Equal(oldFileMeta.Timestamp) {
		log15.Info("Skip (Same Timestamp)", "Family", family, "Version", osVer)
		return nil
	}

	// newDeps, oldDeps: {"DEFID": {"cves": {"CVEID": {}}, "packages": {"PACKNAME": {}}}}
	newDeps := map[string]map[string]map[string]struct{}{}
	depKey := fmt.Sprintf(depKeyFormat, family, osVer)
	oldDepsStr, err := r.conn.Get(ctx, depKey).Result()
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

	for idx := range chunkSlice(len(root.Definitions), 10) {
		pipe := r.conn.Pipeline()
		defKey := fmt.Sprintf(defKeyFormat, family, osVer)
		for _, def := range root.Definitions[idx.From:idx.To] {
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
				cveKey := fmt.Sprintf(cveKeyFormat, family, osVer, cve.CveID)
				if err := pipe.SAdd(ctx, cveKey, def.DefinitionID).Err(); err != nil {
					return fmt.Errorf("Failed to SAdd CVE-Ir. err: %s", err)
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
				if _, ok := oldDeps[def.DefinitionID]; ok {
					if _, ok := oldDeps[def.DefinitionID]["cves"]; ok {
						delete(oldDeps[def.DefinitionID]["cves"], cve.CveID)
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
				pkgKey := fmt.Sprintf(pkgKeyFormat, family, osVer, pkgName)

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
				if _, ok := oldDeps[def.DefinitionID]; ok {
					if _, ok := oldDeps[def.DefinitionID]["packages"]; ok {
						delete(oldDeps[def.DefinitionID]["packages"], pkgName)
					}
				}
			}

			if _, ok := oldDeps[def.DefinitionID]; ok {
				if _, ok := oldDeps[def.DefinitionID]["cves"]; ok {
					if len(oldDeps[def.DefinitionID]["cves"]) == 0 {
						delete(oldDeps[def.DefinitionID], "cves")
					}
				}

				if _, ok := oldDeps[def.DefinitionID]["packages"]; ok {
					if len(oldDeps[def.DefinitionID]["packages"]) == 0 {
						delete(oldDeps[def.DefinitionID], "packages")
					}
				}

				if len(oldDeps[def.DefinitionID]) == 0 {
					delete(oldDeps, def.DefinitionID)
				}
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
	}

	pipe := r.conn.Pipeline()
	for defID, definitions := range oldDeps {
		for cveID := range definitions["cves"] {
			if err := pipe.SRem(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, cveID), defID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		for pack := range definitions["packages"] {
			if err := pipe.SRem(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, pack), defID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		if err := pipe.HDel(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defID).Err(); err != nil {
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
	if err := pipe.Set(ctx, fmt.Sprintf(lastModifiedKeyFormat, family, osVer), root.Timestamp.Format("2006-01-02T15:04:05Z"), time.Duration(expire*uint(time.Second))).Err(); err != nil {
		return fmt.Errorf("Failed to Set LastModifiedKey. err: %s", err)
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	return nil
}

// InsertFileMeta inserts FileMeta
func (r *RedisDriver) InsertFileMeta(meta models.FileMeta) error {
	if err := r.conn.HSet(context.Background(), fileMetaKey, meta.FileName, meta.Timestamp.Format("2006-01-02T15:04:05Z")).Err(); err != nil {
		return fmt.Errorf("Failed to HSet. err: %s", err)
	}
	return nil
}

// GetFileMeta :
func (r *RedisDriver) GetFileMeta(meta models.FileMeta) (models.FileMeta, error) {
	timeStr, err := r.conn.HGet(context.Background(), fileMetaKey, meta.FileName).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return models.FileMeta{}, fmt.Errorf("Failed to HGet. err: %s", err)
		}
		return models.FileMeta{FileName: meta.FileName, Timestamp: time.Time{}}, nil
	}

	fileTime, err := time.Parse("2006-01-02T15:04:05Z", timeStr)
	if err != nil {
		return models.FileMeta{}, fmt.Errorf("Failed to parse models.FileMeta.Timestamp. err: %s", err)
	}

	return models.FileMeta{FileName: meta.FileName, Timestamp: fileTime}, nil
}

// CountDefs counts the number of definitions specified by args
func (r *RedisDriver) CountDefs(family, osVer string) (int, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return 0, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	count, err := r.conn.HLen(context.Background(), fmt.Sprintf(defKeyFormat, family, osVer)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return 0, fmt.Errorf("Failed to HLen. err: %s", err)
		}
		return 0, nil
	}

	return int(count), nil
}

// GetLastModified get last modified time of OVAL in roots
func (r *RedisDriver) GetLastModified(family, osVer string) (time.Time, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return time.Time{}, fmt.Errorf("Failed to formatFamilyAndOSVer. err: %s", err)
	}

	lastModifiedStr, err := r.conn.Get(context.Background(), fmt.Sprintf(lastModifiedKeyFormat, family, osVer)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return time.Time{}, fmt.Errorf("Failed to Get. err: %s", err)
		}
		return time.Now().AddDate(-100, 0, 0), nil
	}

	lastModified, err := time.Parse("2006-01-02T15:04:05Z", lastModifiedStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("Failed to parse LastModifier. err: %s", err)
	}
	return lastModified, nil
}

// IsGovalDictModelV1 determines if the DB was created at the time of goval-dictionary Model v1
func (r *RedisDriver) IsGovalDictModelV1() (bool, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return false, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		keys, _, err := r.conn.Scan(ctx, 0, "OVAL#*", 1).Result()
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
func (r *RedisDriver) GetFetchMeta() (*models.FetchMeta, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GovalDictRevision: c.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	revision, err := r.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGet Revision. err: %s", err)
	}

	verstr, err := r.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
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
func (r *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return r.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": fetchMeta.GovalDictRevision, "SchemaVersion": fetchMeta.SchemaVersion}).Err()
}
