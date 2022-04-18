package commands

import (
	"encoding/json"
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	c "github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/db"
	fetcher "github.com/vulsio/goval-dictionary/fetcher/redhat"
	"github.com/vulsio/goval-dictionary/log"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/models/redhat"
)

// fetchRedHatCmd is Subcommand for fetch RedHat OVAL
var fetchRedHatCmd = &cobra.Command{
	Use:   "redhat",
	Short: "Fetch Vulnerability dictionary from RedHat",
	Long:  `Fetch Vulnerability dictionary from RedHat`,
	RunE:  fetchRedHat,
}

func init() {
	fetchCmd.AddCommand(fetchRedHatCmd)
}

func fetchRedHat(_ *cobra.Command, args []string) (err error) {
	if err := log.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	if len(args) == 0 {
		return xerrors.New("Failed to fetch redhat command. err: specify versions to fetch")
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

	log15.Info("Fetching Repository to CPE data")
	result, err := fetcher.FetchRepositoryToCPEFile()
	if err != nil {
		return xerrors.Errorf("Failed to fetch redhat Repository to CPE file. err: %w", err)
	}

	var repoToCPEJSON redhat.RepositoryToCPEJSON
	if err := json.Unmarshal(result.Body, &repoToCPEJSON); err != nil {
		return xerrors.Errorf("Failed to unmarshal Repository to CPE json. err: %w", err)
	}
	repoToCPE := redhat.ConvertRepositoryToCPEToModel(repoToCPEJSON)
	if err := driver.InsertRedHatRepositoryToCPE(repoToCPE); err != nil {
		return xerrors.Errorf("Failed to insert OVAL. err: %w", err)
	}
	log15.Info("Updated Repository to CPE data")

	// Distinct
	vers := []string{}
	v := map[string]bool{}
	for _, arg := range args {
		majorVer := arg
		if strings.Contains(arg, "-") {
			if !strings.HasSuffix(arg, "-eus") && !strings.HasSuffix(arg, "-tus") && !strings.HasSuffix(arg, "-aus") && !strings.HasSuffix(arg, "-els") {
				return xerrors.Errorf("Only EUS, TUS, AUS and ELS is supported. arg: %s", arg)
			}
			majorVer = arg[:1]
		}
		ver, err := strconv.Atoi(majorVer)
		if err != nil || ver < 5 {
			return xerrors.Errorf("Specify version to fetch (from 5 to latest RHEL version). arg: %s", arg)
		}
		v[arg] = true
	}
	for k := range v {
		vers = append(vers, k)
	}

	resultsPerVersion, err := fetcher.FetchFiles(vers)
	if err != nil {
		return xerrors.Errorf("Failed to fetch files. err: %w", err)
	}

	rootsPerVersion := map[string][]redhat.Root{}
	for v, rs := range resultsPerVersion {
		for _, r := range rs {
			root := redhat.Root{}
			if err = xml.Unmarshal(r.Body, &root); err != nil {
				return xerrors.Errorf("Failed to unmarshal xml. url: %s, err: %w", r.URL, err)
			}

			log15.Info("Fetched", "File", r.URL[strings.LastIndex(r.URL, "/")+1:], "Count", len(root.Definitions.Definitions), "Timestamp", root.Generator.Timestamp)
			ts, err := time.Parse("2006-01-02T15:04:05", root.Generator.Timestamp)
			if err != nil {
				return xerrors.Errorf("Failed to parse timestamp. url: %s, timestamp: %s, err: %w", r.URL, root.Generator.Timestamp, err)
			}
			if ts.Before(time.Now().AddDate(0, 0, -3)) {
				log15.Warn("The fetched OVAL has not been updated for 3 days, the OVAL URL may have changed, please register a GitHub issue.", "GitHub", "https://github.com/vulsio/goval-dictionary/issues", "OVAL", r.URL, "Timestamp", root.Generator.Timestamp)
			}

			rootsPerVersion[v] = append(rootsPerVersion[v], root)
		}
	}

	for v, roots := range rootsPerVersion {
		defs, err := redhat.ConvertToModel(roots)
		if err != nil {
			return xerrors.Errorf("Failed to convert from OVAL to goval-dictionary model. err: %w", err)
		}
		root := models.Root{
			Family:      c.RedHat,
			OSVersion:   v,
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
