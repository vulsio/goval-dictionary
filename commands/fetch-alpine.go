package commands

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/xerrors"
	yaml "gopkg.in/yaml.v2"

	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	if len(args) == 0 {
		log15.Error("Specify versions to fetch")
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

	driver, locked, err := db.NewDB(c.Alpine, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
	}

	results, err := fetcher.FetchAlpineFiles(vers)
	if err != nil {
		log15.Error("Failed to fetch files", "err", err)
		return err
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
			log15.Error("Failed to unmarshal yml.", "err", err)
			return err
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

	// pp.Println(m)

	for target, t := range m {
		root := models.Root{
			Family:      c.Alpine,
			OSVersion:   target,
			Definitions: t.defs,
			Timestamp:   time.Now(),
		}

		fmeta := models.FetchMeta{
			Timestamp: time.Now(),
			FileName:  t.url,
		}

		log15.Info(fmt.Sprintf("%d CVEs", len(t.defs)))
		if err := driver.InsertOval(c.Alpine, &root, fmeta); err != nil {
			log15.Error("Failed to insert meta.", "err", err)
			return err
		}
		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log15.Error("Failed to insert meta", "err", err)
			return err
		}
		log15.Info("Finish", "Updated", len(root.Definitions))
	}

	return nil
}

func unmarshalYml(data []byte) (*models.AlpineSecDB, error) {
	t := models.AlpineSecDB{}
	err := yaml.Unmarshal([]byte(data), &t)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal: %s", err)
	}
	return &t, nil
}
