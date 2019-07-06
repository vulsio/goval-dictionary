package commands

import (
	"context"
	"encoding/xml"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/google/subcommands"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/ymomoi/goval-parser/oval"
)

// FetchOracleCmd is Subcommand for fetch Oracle OVAL
type FetchOracleCmd struct {
	Debug     bool
	DebugSQL  bool
	Quiet     bool
	NoDetails bool
	LogDir    string
	LogJSON   bool
	DBPath    string
	DBType    string
	HTTPProxy string
}

// Name return subcommand name
func (*FetchOracleCmd) Name() string { return "fetch-oracle" }

// Synopsis return synopsis
func (*FetchOracleCmd) Synopsis() string { return "Fetch Vulnerability dictionary from Oracle" }

// Usage return usage
func (*FetchOracleCmd) Usage() string {
	return `fetch-oracle:
	fetch-oracle
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-no-details]
		[-log-dir=/path/to/log]
		[-log-json]

For details, see https://github.com/kotakanbe/goval-dictionary#usage-fetch-oval-data-from-oracle
	$ goval-dictionary fetch-oracle

`
}

// SetFlags set flag
func (p *FetchOracleCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.Debug, "debug", false, "debug mode")
	f.BoolVar(&p.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&p.Quiet, "quiet", false, "quiet mode (no output)")
	f.BoolVar(&p.NoDetails, "no-details", false, "without vulnerability details")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&p.LogJSON, "log-json", false, "output log as JSON")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.DBPath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&p.DBType, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3, mysql, postgres or redis supported)")

	f.StringVar(
		&p.HTTPProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)
}

// Execute execute
func (p *FetchOracleCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Quiet = p.Quiet
	c.Conf.DebugSQL = p.DebugSQL
	c.Conf.Debug = p.Debug
	c.Conf.DBPath = p.DBPath
	c.Conf.DBType = p.DBType
	c.Conf.HTTPProxy = p.HTTPProxy
	c.Conf.NoDetails = p.NoDetails

	util.SetLogger(p.LogDir, c.Conf.Quiet, c.Conf.Debug, p.LogJSON)
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	driver, locked, err := db.NewDB(c.Oracle, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL)
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return subcommands.ExitFailure
		}
		log15.Error("Failed to open DB", "err", err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	results, err := fetcher.FetchOracleFiles()
	if err != nil {
		log15.Error("Failed to fetch files", "err", err)
		return subcommands.ExitFailure
	}

	for _, r := range results {
		ovalroot := oval.Root{}
		if err = xml.Unmarshal(r.Body, &ovalroot); err != nil {
			log15.Error("Failed to unmarshal", "url", r.URL, "err", err)
			return subcommands.ExitUsageError
		}
		log15.Info("Fetched", "URL", r.URL, "OVAL definitions", len(ovalroot.Definitions.Definitions))

		//  var timeformat = "2006-01-02T15:04:05.999-07:00"
		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, strings.Split(ovalroot.Generator.Timestamp, ".")[0])
		if err != nil {
			panic(err)
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		roots := models.ConvertOracleToModel(&ovalroot)
		for _, root := range roots {
			root.Timestamp = time.Now()
			if err := driver.InsertOval(c.Oracle, &root, fmeta); err != nil {
				log15.Error("Failed to insert oval", "err", err)
				return subcommands.ExitFailure
			}
		}
		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log15.Error("Failed to insert meta", "err", err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}
