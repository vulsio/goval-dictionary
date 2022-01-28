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

// fetchSUSECmd is Subcommand for fetch SUSE OVAL
var fetchSUSECmd = &cobra.Command{
	Use:   "suse",
	Short: "Fetch Vulnerability dictionary from SUSE",
	Long: `Fetch Vulnerability dictionary from SUSE
	
$ goval-dictionary fetch suse --suse-type opensuse 10.2 10.3 11.0 11.1 11.2 11.3 11.4 12.1 12.2 12.3 13.1 13.2
$ goval-dictionary fetch suse --suse-type opensuse-leap 42.1 42.2 42.3 15.0 15.1 15.2 15.3
$ goval-dictionary fetch suse --suse-type suse-enterprise-server 9 10 11 12 15
$ goval-dictionary fetch suse --suse-type suse-enterprise-desktop 10 11 12 15
$ goval-dictionary fetch suse --suse-type suse-openstack-cloud 6 7 8 9
`,
	RunE: fetchSUSE,
}

func init() {
	fetchCmd.AddCommand(fetchSUSECmd)

	fetchSUSECmd.PersistentFlags().String("suse-type", "opensuse-leap", "Fetch SUSE Type(choices: opensuse, opensuse-leap, suse-enterprise-server, suse-enterprise-desktop, suse-openstack-cloud)")
	_ = viper.BindPFlag("suse-type", fetchSUSECmd.PersistentFlags().Lookup("suse-type"))
}

func fetchSUSE(_ *cobra.Command, args []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	if len(args) == 0 {
		return xerrors.New("Failed to fetch suse command. err: specify versions to fetch. Oval files are here: http://ftp.suse.com/pub/projects/security/oval/")
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

	var suseType string
	switch viper.GetString("suse-type") {
	case "opensuse":
		suseType = c.OpenSUSE
	case "opensuse-leap":
		suseType = c.OpenSUSELeap
	case "suse-enterprise-server":
		suseType = c.SUSEEnterpriseServer
	case "suse-enterprise-desktop":
		suseType = c.SUSEEnterpriseDesktop
	case "suse-openstack-cloud":
		suseType = c.SUSEOpenstackCloud
	default:
		return xerrors.Errorf("Specify SUSE type to fetch. Available SUSE Type: opensuse, opensuse-leap, suse-enterprise-server, suse-enterprise-desktop, suse-openstack-cloud")
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

	var results []fetcher.FetchResult
	results, err = fetcher.FetchSUSEFiles(suseType, vers)
	if err != nil {
		return xerrors.Errorf("Failed to fetch files. err: %w", err)
	}

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

		ss := strings.Split(r.URL, "/")
		roots := models.ConvertSUSEToModel(ss[len(ss)-1], &ovalroot)
		for _, root := range roots {
			root.Timestamp = time.Now()
			if err := driver.InsertOval(&root); err != nil {
				return xerrors.Errorf("Failed to insert OVAL. err: %w", err)
			}
			log15.Info("Finish", "Updated", len(root.Definitions))
		}
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. err: %w", err)
	}

	return nil
}
