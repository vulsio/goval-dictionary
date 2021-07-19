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

// fetchDebianCmd is Subcommand for fetch Debian OVAL
var fetchDebianCmd = &cobra.Command{
	Use:   "debian",
	Short: "Fetch Vulnerability dictionary from Debian",
	Long:  `Fetch Vulnerability dictionary from Debian`,
	RunE:  fetchDebian,
}

func init() {
	fetchCmd.AddCommand(fetchDebianCmd)
}

func fetchDebian(cmd *cobra.Command, args []string) (err error) {
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	if len(args) == 0 {
		log15.Error("Specify versions to fetch")
		return xerrors.New("Failed to fetch debian command. err: specify versions to fetch")
	}

	driver, locked, err := db.NewDB(c.Debian, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
	}
	defer func() {
		_ = driver.CloseDB()
	}()

	// Distinct
	vers := []string{}
	v := map[string]bool{}
	for _, arg := range args {
		v[arg] = true
	}
	for k := range v {
		vers = append(vers, k)
	}

	results, err := fetcher.FetchDebianFiles(vers)
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

		defs := models.ConvertDebianToModel(&ovalroot)

		var timeformat = "2006-01-02T15:04:05"
		var t time.Time
		t, err = time.Parse(timeformat, strings.Split(ovalroot.Generator.Timestamp, ".")[0])
		if err != nil {
			log15.Error("Failed to parse timestamp", "url", r.URL, "err", err)
			return err
		}

		root := models.Root{
			Family:      c.Debian,
			OSVersion:   r.Target,
			Definitions: defs,
			Timestamp:   time.Now(),
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		if err := driver.InsertOval(c.Debian, &root, fmeta); err != nil {
			log15.Error("Failed to insert oval", "err", err)
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
