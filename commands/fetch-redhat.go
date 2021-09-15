package commands

import (
	"encoding/xml"
	"strconv"
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

func fetchRedHat(cmd *cobra.Command, args []string) (err error) {
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	if len(args) == 0 {
		log15.Error("Specify versions to fetch")
		return xerrors.New("Failed to fetch redhat command. err: specify versions to fetch")
	}

	driver, locked, err := db.NewDB(c.RedHat, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		log15.Error("Failed to get FetchMeta from DB.", "err", err)
		return err
	}
	if fetchMeta.OutDated() {
		log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
		return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
	}

	// Distinct
	vers := []string{}
	v := map[string]bool{}
	for _, arg := range args {
		ver, err := strconv.Atoi(arg)
		if err != nil || ver < 5 {
			log15.Error("Specify version to fetch (from 5 to latest RHEL version)", "arg", arg)
			return err
		}
		v[arg] = true
	}
	for k := range v {
		vers = append(vers, k)
	}

	results, err := fetcher.FetchRedHatFiles(vers)
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
		defs := models.ConvertRedHatToModel(&ovalroot)

		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, ovalroot.Generator.Timestamp)
		if err != nil {
			log15.Error("Failed to parse time", "err", err)
			return err
		}

		root := models.Root{
			Family:      c.RedHat,
			OSVersion:   r.Target,
			Definitions: defs,
			Timestamp:   time.Now(),
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FileMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		if err := driver.InsertOval(c.RedHat, &root, fmeta); err != nil {
			log15.Error("Failed to insert oval", "err", err)
			return err
		}
		if err := driver.InsertFileMeta(fmeta); err != nil {
			log15.Error("Failed to insert meta", "err", err)
			return err
		}
		log15.Info("Finish", "Updated", len(root.Definitions))
	}

	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		log15.Error("Failed to upsert FetchMeta to DB.", "err", err)
		return err
	}

	return nil
}
