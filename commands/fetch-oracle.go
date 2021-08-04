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
)

// fetchOracleCmd is Subcommand for fetch Oracle OVAL
var fetchOracleCmd = &cobra.Command{
	Use:   "oracle",
	Short: "Fetch Vulnerability dictionary from Oracle",
	Long:  `Fetch Vulnerability dictionary from Oracle`,
	RunE:  fetchOracle,
}

func init() {
	fetchCmd.AddCommand(fetchOracleCmd)
}

func fetchOracle(cmd *cobra.Command, args []string) (err error) {
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	driver, locked, err := db.NewDB(c.Oracle, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
	}

	results, err := fetcher.FetchOracleFiles()
	if err != nil {
		log15.Error("Failed to fetch files", "err", err)
		return err
	}

	osVerDefs := map[string][]models.Definition{}
	fmeta := models.FetchMeta{}
	for _, r := range results {
		ovalroot := oval.Root{}
		if err = xml.Unmarshal(r.Body, &ovalroot); err != nil {
			log15.Error("Failed to unmarshal", "url", r.URL, "err", err)
			return err
		}
		log15.Info("Fetched", "URL", r.URL, "OVAL definitions", len(ovalroot.Definitions.Definitions))

		//  var timeformat = "2006-01-02T15:04:05.999-07:00"
		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, strings.Split(ovalroot.Generator.Timestamp, ".")[0])
		if err != nil {
			log15.Error("Failed to parse time", "err", err)
			return err
		}

		ss := strings.Split(r.URL, "/")
		fmeta = models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		for osVer, defs := range models.ConvertOracleToModel(&ovalroot) {
			osVerDefs[osVer] = append(osVerDefs[osVer], defs...)
		}
	}

	for osVer, defs := range osVerDefs {
		root := models.Root{
			Family:      c.Oracle,
			OSVersion:   osVer,
			Definitions: models.AggregateAffectedPackages(defs),
			Timestamp:   time.Now(),
		}

		if err := driver.InsertOval(c.Oracle, &root, fmeta); err != nil {
			log15.Error("Failed to insert oval", "err", err)
			return err
		}
		log15.Info("Finish", "Updated", len(root.Definitions))
	}

	if err := driver.InsertFetchMeta(fmeta); err != nil {
		log15.Error("Failed to insert meta", "err", err)
		return err
	}

	return nil
}
