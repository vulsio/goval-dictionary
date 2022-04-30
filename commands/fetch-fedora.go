package commands

import (
	"fmt"
	"strconv"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	c "github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/db"
	fetcher "github.com/vulsio/goval-dictionary/fetcher/fedora"
	"github.com/vulsio/goval-dictionary/log"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/models/fedora"
)

// fetchFedoraCmd is Subcommand for fetch Fedora OVAL
var fetchFedoraCmd = &cobra.Command{
	Use:   "fedora",
	Short: "Fetch Vulnerability dictionary from Fedora",
	Long:  `Fetch Vulnerability dictionary from Fedora`,
	RunE:  fetchFedora,
}

func init() {
	fetchCmd.AddCommand(fetchFedoraCmd)
}

func fetchFedora(_ *cobra.Command, args []string) (err error) {
	if err := log.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	if len(args) == 0 {
		return xerrors.New("Failed to fetch fedora command. err: specify versions to fetch")
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to open DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}
	defer func() {
		err := driver.CloseDB()
		if err != nil {
			log15.Error("Failed to close DB", "err", err)
		}
	}()

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

	// Distinct
	vers := []string{}
	v := map[string]bool{}
	for _, arg := range args {
		ver, err := strconv.Atoi(arg)
		// Fedora versions prior to version 32 have no update information
		// https://dl.fedoraproject.org/pub/fedora/linux/updates/
		if err != nil || ver < 32 {
			return xerrors.Errorf("Specify version to fetch (from 32 to latest Fedora version). arg: %s", arg)
		}
		v[arg] = true
	}
	for k := range v {
		vers = append(vers, k)
	}

	uinfos, err := fetcher.FetchUpdateInfosFedora(vers)
	if err != nil {
		return xerrors.Errorf("Failed to fetch files. err: %w", err)
	}

	for k, v := range uinfos {
		root := models.Root{
			Family:      c.Fedora,
			OSVersion:   k,
			Definitions: fedora.ConvertToModel(v),
			Timestamp:   time.Now(),
		}
		log15.Info(fmt.Sprintf("%d CVEs for Fedora %s. Inserting to DB", len(root.Definitions), k))
		if err := execute(driver, &root); err != nil {
			return xerrors.Errorf("Failed to Insert Fedora %s. err: %w", k, err)
		}
	}
	return nil
}
