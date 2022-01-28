package commands

import (
	"encoding/xml"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	c "github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/db"
	"github.com/vulsio/goval-dictionary/fetcher"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/util"
	"github.com/ymomoi/goval-parser/oval"
	"golang.org/x/xerrors"
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

func fetchOracle(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
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
	// If the fetch fails the first time (without SchemaVersion), the DB needs to be cleaned every time, so insert SchemaVersion.
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. err: %w", err)
	}

	results, err := fetcher.FetchOracleFiles()
	if err != nil {
		return xerrors.Errorf("Failed to fetch files. err: %w", err)
	}

	osVerDefs := map[string][]models.Definition{}
	for _, r := range results {
		ovalroot := oval.Root{}
		if err = xml.Unmarshal(r.Body, &ovalroot); err != nil {
			return xerrors.Errorf("Failed to unmarshal xml. url: %s, err: %w", r.URL, err)
		}
		log15.Info("Fetched", "File", r.URL[strings.LastIndex(r.URL, "/")+1:], "Count", len(ovalroot.Definitions.Definitions), "Timestamp", ovalroot.Generator.Timestamp)
		ts, err := time.Parse("2006-01-02T15:04:05", ovalroot.Generator.Timestamp)
		if err != nil {
			return xerrors.Errorf("Failed to parse timestamp. url: %s, timestamp: %s, err: %w", r.URL, err, ovalroot.Generator.Timestamp)
		}
		if ts.Before(time.Now().AddDate(0, 0, -3)) {
			log15.Warn("The fetched OVAL has not been updated for 3 days, the OVAL URL may have changed, please register a GitHub issue.", "GitHub", "https://github.com/vulsio/goval-dictionary/issues", "OVAL", r.URL, "Timestamp", ovalroot.Generator.Timestamp)
		}

		for osVer, defs := range models.ConvertOracleToModel(&ovalroot) {
			osVerDefs[osVer] = append(osVerDefs[osVer], defs...)
		}
	}

	for osVer, defs := range osVerDefs {
		root := models.Root{
			Family:      c.Oracle,
			OSVersion:   osVer,
			Definitions: defs,
			Timestamp:   time.Now(),
		}

		if err := driver.InsertOval(&root); err != nil {
			return xerrors.Errorf("Failed to insert OVAL. err: %w", err)
		}
		log15.Info("Finish", "Updated", len(root.Definitions))
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. err: %w", err)
	}

	return nil
}
