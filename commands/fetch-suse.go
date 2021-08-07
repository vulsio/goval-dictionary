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

	fetchSUSECmd.PersistentFlags().String("suse-type", "opensuse-leap", "Fetch SUSE Type")
	_ = viper.BindPFlag("suse-type", fetchSUSECmd.PersistentFlags().Lookup("suse-type"))
}

func fetchSUSE(cmd *cobra.Command, args []string) (err error) {
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	if len(args) == 0 {
		log15.Error("Specify versions to fetch. Oval files are here: http://ftp.suse.com/pub/projects/security/oval/")
		return xerrors.New("Failed to fetch suse command. err: specify versions to fetch")
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
		log15.Error("Specify SUSE type to fetch. Available SUSE Type: opensuse, opensuse-leap, suse-enterprise-server, suse-enterprise-desktop, suse-openstack-cloud")
		return xerrors.New("Failed to fetch suse command. err: specify SUSE type to fetch")
	}

	driver, locked, err := db.NewDB(suseType, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
	}

	var results []fetcher.FetchResult
	results, err = fetcher.FetchSUSEFiles(suseType, vers)
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

		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, ovalroot.Generator.Timestamp)
		if err != nil {
			log15.Error("Failed to parse time", "err", err)
			return err
		}
		ss := strings.Split(r.URL, "/")
		filename := ss[len(ss)-1]
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  filename,
		}

		roots := models.ConvertSUSEToModel(filename, &ovalroot)
		for _, root := range roots {
			root.Timestamp = time.Now()
			if err := driver.NewOvalDB(root.Family); err != nil {
				log15.Error("Failed to NewOvalDB for Family found in SUSE OVAL", "err", err)
				return err
			}

			if err := driver.InsertOval(root.Family, &root, fmeta); err != nil {
				log15.Error("Failed to insert oval", "err", err)
				return err
			}
			log15.Info("Finish", "Updated", len(root.Definitions))
		}

		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log15.Error("Failed to insert meta", "err", err)
			return err
		}
	}

	return nil
}
