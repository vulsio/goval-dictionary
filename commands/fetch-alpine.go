package commands

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/xerrors"
	yaml "gopkg.in/yaml.v2"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	c "github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/db"
	"github.com/vulsio/goval-dictionary/fetcher"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/util"
)

// fetchAlpineCmd is Subcommand for fetch Alpine secdb
// https://secdb.alpinelinux.org/
var fetchAlpineCmd = &cobra.Command{
	Use:   "alpine",
	Short: "Fetch Vulnerability dictionary from Alpine secdb",
	Long:  `Fetch Vulnerability dictionary from Alpine secdb`,
	RunE:  fetchAlpine,
}

func init() {
	fetchCmd.AddCommand(fetchAlpineCmd)
}

func fetchAlpine(cmd *cobra.Command, args []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	if len(args) == 0 {
		return xerrors.New("Failed to fetch alpine command. err: specify versions to fetch")
	}

	// Distinct
	v := map[string]bool{}
	vers := []string{}
	for _, arg := range args {
		v[arg] = true
	}
	for k := range v {
		vers = append(vers, k)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to open DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to Insert CVEs into DB. SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. err: %w", err)
	}

	results, err := fetcher.FetchAlpineFiles(vers)
	if err != nil {
		return xerrors.Errorf("Failed to fetch files. err: %w", err)
	}

	// Join community.yaml, main.yaml
	type T struct {
		url  string
		defs []models.Definition
	}
	m := map[string]T{}
	for _, r := range results {
		secdb, err := unmarshalYml(r.Body)
		if err != nil {
			return xerrors.Errorf("Failed to unmarshal yml. err: %w", err)
		}

		defs := models.ConvertAlpineToModel(secdb)
		if t, ok := m[r.Target]; ok {
			t.defs = append(t.defs, defs...)
			m[r.Target] = t
		} else {
			ss := strings.Split(r.URL, "/")
			m[r.Target] = T{
				url:  strings.Join(ss[len(ss)-3:len(ss)-1], "/"),
				defs: defs,
			}
		}
	}

	for target, t := range m {
		root := models.Root{
			Family:      c.Alpine,
			OSVersion:   target,
			Definitions: t.defs,
			Timestamp:   time.Now(),
		}

		log15.Info(fmt.Sprintf("%d CVEs", len(t.defs)))
		if err := driver.InsertOval(&root); err != nil {
			return xerrors.Errorf("Failed to insert OVAL. err: %w", err)
		}
		log15.Info("Finish", "Updated", len(root.Definitions))
	}

	return nil
}

func unmarshalYml(data []byte) (*models.AlpineSecDB, error) {
	t := models.AlpineSecDB{}
	err := yaml.Unmarshal([]byte(data), &t)
	if err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal: %w", err)
	}
	return &t, nil
}
