package commands

import (
	"encoding/xml"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ymomoi/goval-parser/oval"
	"golang.org/x/xerrors"
)

// fetchUbuntuCmd is Subcommand for fetch Ubuntu OVAL
var fetchUbuntuCmd = &cobra.Command{
	Use:   "ubuntu",
	Short: "Fetch Vulnerability dictionary from Ubuntu",
	Long:  `Fetch Vulnerability dictionary from Ubuntu`,
	RunE:  fetchUbuntu,
}

func init() {
	fetchCmd.AddCommand(fetchUbuntuCmd)
}

func fetchUbuntu(cmd *cobra.Command, args []string) (err error) {
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	if len(args) == 0 {
		log15.Error("Specify versions to fetch")
		return xerrors.New("Failed to fetch ubuntu command. err: specify versions to fetch")
	}

	driver, locked, err := db.NewDB(c.Ubuntu, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
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

	results, err := fetcher.FetchUbuntuFiles(vers)
	if err != nil {
		log15.Error("Failed to fetch files", "err", err)
		return err
	}

	for _, r := range results {
		ovalroot := oval.Root{}
		if err = xml.Unmarshal(r.Body, &ovalroot); err != nil {
			log15.Error("Failed to unmarshal", "url", r.URL, "err", err)
			return err
		}
		log15.Info("Fetched", "URL", r.URL, "OVAL definitions", len(ovalroot.Definitions.Definitions))

		defs := models.ConvertUbuntuToModel(&ovalroot)

		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, ovalroot.Generator.Timestamp)
		if err != nil {
			log15.Error("Failed to parse time", "err", err)
			return err
		}

		root := models.Root{
			Family:      c.Ubuntu,
			OSVersion:   r.Target,
			Definitions: defs,
			Timestamp:   time.Now(),
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		if err := driver.InsertOval(c.Ubuntu, &root, fmeta); err != nil {
			log15.Error("Failed to insert OVAL", "err", err)
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
