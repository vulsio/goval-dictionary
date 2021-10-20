package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	c "github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/models"
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
	if err := r.connectRedis(dbPath); err != nil {
		return false, xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
	}
	return false, nil
}

func (r *RedisDriver) connectRedis(dbPath string) error {
	option, err := redis.ParseURL(dbPath)
	if err != nil {
		return xerrors.Errorf("Failed to parse url. err: %w", err)
	}
	r.conn = redis.NewClient(option)
	return r.conn.Ping(context.Background()).Err()
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
		return nil, xerrors.Errorf("Failed to formatFamilyAndOSVer. err: %w", err)
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
				return nil, xerrors.Errorf("Failed to DBSize. err: %w", err)
			}

			var cursor uint64
			for {
				var keys []string
				var err error
				keys, cursor, err = r.conn.Scan(ctx, cursor, fmt.Sprintf("%s#%s", key, "*"), dbsize/5).Result()
				if err != nil {
					return nil, xerrors.Errorf("Failed to Scan. err: %w", err)
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
		return nil, xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	defIDs := []string{}
	for _, cmder := range cmders {
		result, err := cmder.(*redis.StringSliceCmd).Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to SMembers. err: %w", err)
		}

		defIDs = append(defIDs, result...)
	}
	if len(defIDs) == 0 {
		return []models.Definition{}, nil
	}

	defStrs, err := r.conn.HMGet(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defIDs...).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HMGet. err: %w", err)
	}

	defs := []models.Definition{}
	for i, defstr := range defStrs {
		if defstr == nil {
			// Only Logging
			// TODO: remove invalid keys
			log15.Error("Failed to HMGet. Some fields do not exist. continue scanning", "Family", family, "Version", osVer, "defID", defIDs[i])
			continue
		}

		def, err := restoreDefinition(defstr.(string), family, osVer, arch)
		if err != nil {
			return nil, xerrors.Errorf("Failed to restoreDefinition. err: %w", err)
		}
		defs = append(defs, def)
	}

	return defs, nil
}

// GetByCveID select OVAL definition related to OS Family, osVer, cveID
func (r *RedisDriver) GetByCveID(family, osVer, cveID, arch string) ([]models.Definition, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return nil, xerrors.Errorf("Failed to formatFamilyAndOSVer. err: %w", err)
	}

	ctx := context.Background()
	defIDs, err := r.conn.SMembers(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, cveID)).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to SMembers. err: %w", err)
	}
	if len(defIDs) == 0 {
		return []models.Definition{}, nil
	}

	defStrs, err := r.conn.HMGet(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defIDs...).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HMGet. err: %w", err)
	}

	defs := []models.Definition{}
	for i, defstr := range defStrs {
		if defstr == nil {
			// Only Logging
			// TODO: remove invalid keys
			log15.Error("Failed to HMGet. Some fields do not exist. continue scanning", "Family", family, "Version", osVer, "defID", defIDs[i])
			continue
		}

		def, err := restoreDefinition(defstr.(string), family, osVer, arch)
		if err != nil {
			return nil, xerrors.Errorf("Failed to restoreDefinition. err: %w", err)
		}
		defs = append(defs, def)
	}

	return defs, nil
}

func restoreDefinition(defstr, family, version, arch string) (models.Definition, error) {
	var def models.Definition
	if err := json.Unmarshal([]byte(defstr), &def); err != nil {
		return models.Definition{}, xerrors.Errorf("Failed to Unmarshal JSON. err: %w", err)
	}

	switch family {
	case c.Amazon, c.Oracle:
		def.AffectedPacks = fileterPacksByArch(def.AffectedPacks, arch)
	case c.RedHat:
		def.AffectedPacks = filterByRedHatMajor(def.AffectedPacks, major(version))
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

// InsertOval inserts OVAL
func (r *RedisDriver) InsertOval(root *models.Root) (err error) {
	ctx := context.Background()
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	family, osVer, err := formatFamilyAndOSVer(root.Family, root.OSVersion)
	if err != nil {
		return xerrors.Errorf("Failed to formatFamilyAndOSVer. err: %w", err)
	}
	log15.Info("Refreshing...", "Family", family, "Version", osVer)

	// newDeps, oldDeps: {"DEFID": {"cves": {"CVEID": {}}, "packages": {"PACKNAME": {}}}}
	newDeps := map[string]map[string]map[string]struct{}{}
	depKey := fmt.Sprintf(depKeyFormat, family, osVer)
	oldDepsStr, err := r.conn.Get(ctx, depKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return xerrors.Errorf("Failed to Get key: %s. err: %w", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return xerrors.Errorf("Failed to unmarshal JSON. err: %w", err)
	}

	bar := pb.StartNew(len(root.Definitions))
	for idx := range chunkSlice(len(root.Definitions), batchSize) {
		pipe := r.conn.Pipeline()
		for _, def := range root.Definitions[idx.From:idx.To] {
			var dj []byte
			if dj, err = json.Marshal(def); err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}

			if err := pipe.HSet(ctx, fmt.Sprintf(defKeyFormat, family, osVer), def.DefinitionID, string(dj)).Err(); err != nil {
				return xerrors.Errorf("Failed to HSet. err: %w", err)
			}
			if _, ok := newDeps[def.DefinitionID]; !ok {
				newDeps[def.DefinitionID] = map[string]map[string]struct{}{"cves": {}, "packages": {}}
			}

			for _, cve := range def.Advisory.Cves {
				if err := pipe.SAdd(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, cve.CveID), def.DefinitionID).Err(); err != nil {
					return xerrors.Errorf("Failed to SAdd CVEID. err: %w", err)
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

				if err := pipe.SAdd(ctx, fmt.Sprintf(pkgKeyFormat, family, osVer, pkgName), def.DefinitionID).Err(); err != nil {
					return xerrors.Errorf("Failed to SAdd Package. err: %w", err)
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
		if _, err = pipe.Exec(ctx); err != nil {
			return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for defID, definitions := range oldDeps {
		for cveID := range definitions["cves"] {
			if err := pipe.SRem(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, cveID), defID).Err(); err != nil {
				return xerrors.Errorf("Failed to SRem. err: %w", err)
			}
		}
		for pack := range definitions["packages"] {
			if err := pipe.SRem(ctx, fmt.Sprintf(cveKeyFormat, family, osVer, pack), defID).Err(); err != nil {
				return xerrors.Errorf("Failed to SRem. err: %w", err)
			}
		}
		if err := pipe.HDel(ctx, fmt.Sprintf(defKeyFormat, family, osVer), defID).Err(); err != nil {
			return xerrors.Errorf("Failed to HDel. err: %w", err)
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return xerrors.Errorf("Failed to Marshal JSON. err: %w", err)
	}
	if err := pipe.Set(ctx, depKey, string(newDepsJSON), 0).Err(); err != nil {
		return xerrors.Errorf("Failed to Set depkey. err: %w", err)
	}
	if err := pipe.Set(ctx, fmt.Sprintf(lastModifiedKeyFormat, family, osVer), root.Timestamp.Format("2006-01-02T15:04:05Z"), 0).Err(); err != nil {
		return xerrors.Errorf("Failed to Set LastModifiedKey. err: %w", err)
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	return nil
}

// CountDefs counts the number of definitions specified by args
func (r *RedisDriver) CountDefs(family, osVer string) (int, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return 0, xerrors.Errorf("Failed to formatFamilyAndOSVer. err: %w", err)
	}

	count, err := r.conn.HLen(context.Background(), fmt.Sprintf(defKeyFormat, family, osVer)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return 0, xerrors.Errorf("Failed to HLen. err: %w", err)
		}
		return 0, nil
	}

	return int(count), nil
}

// GetLastModified get last modified time of OVAL in roots
func (r *RedisDriver) GetLastModified(family, osVer string) (time.Time, error) {
	family, osVer, err := formatFamilyAndOSVer(family, osVer)
	if err != nil {
		return time.Time{}, xerrors.Errorf("Failed to formatFamilyAndOSVer. err: %w", err)
	}

	lastModifiedStr, err := r.conn.Get(context.Background(), fmt.Sprintf(lastModifiedKeyFormat, family, osVer)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return time.Time{}, xerrors.Errorf("Failed to Get. err: %w", err)
		}
		return time.Now().AddDate(-100, 0, 0), nil
	}

	lastModified, err := time.Parse("2006-01-02T15:04:05Z", lastModifiedStr)
	if err != nil {
		return time.Time{}, xerrors.Errorf("Failed to parse LastModifier. err: %w", err)
	}
	return lastModified, nil
}

// IsGovalDictModelV1 determines if the DB was created at the time of goval-dictionary Model v1
func (r *RedisDriver) IsGovalDictModelV1() (bool, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return false, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		keys, _, err := r.conn.Scan(ctx, 0, "OVAL#*", 1).Result()
		if err != nil {
			return false, xerrors.Errorf("Failed to Scan. err: %w", err)
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
		return nil, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GovalDictRevision: c.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	revision, err := r.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet Revision. err: %w", err)
	}

	verstr, err := r.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet SchemaVersion. err: %w", err)
	}
	version, err := strconv.ParseUint(verstr, 10, 8)
	if err != nil {
		return nil, xerrors.Errorf("Failed to ParseUint. err: %w", err)
	}

	return &models.FetchMeta{GovalDictRevision: revision, SchemaVersion: uint(version)}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return r.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": fetchMeta.GovalDictRevision, "SchemaVersion": fetchMeta.SchemaVersion}).Err()
}
