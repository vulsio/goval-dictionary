package commands

import (
	"context"
	"encoding/xml"
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/ymomoi/goval-parser/oval"
)

// FetchOracleCmd is Subcommand for fetch Oracle OVAL
type FetchOracleCmd struct {
	Debug     bool
	DebugSQL  bool
	Quiet     bool
	LogDir    string
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
		[-log-dir=/path/to/log]

For details, see https://github.com/kotakanbe/goval-dictionary#usage-fetch-oval-data-from-oracle
	$ goval-dictionary fetch-oracle

`
}

// SetFlags set flag
func (p *FetchOracleCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.Debug, "debug", false, "debug mode")
	f.BoolVar(&p.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&p.Quiet, "quiet", false, "quiet mode (no output)")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")

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
	if c.Conf.Quiet {
		log.Initialize(p.LogDir, ioutil.Discard)
	} else {
		log.Initialize(p.LogDir, os.Stderr)
	}

	c.Conf.DebugSQL = p.DebugSQL
	c.Conf.Debug = p.Debug
	if c.Conf.Debug {
		log.SetDebug()
	}

	c.Conf.DBPath = p.DBPath
	c.Conf.DBType = p.DBType
	c.Conf.HTTPProxy = p.HTTPProxy

	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	results, err := fetcher.FetchOracleFiles()
	if err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	var driver db.DB
	if driver, err = db.NewDB(c.Oracle, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	for _, r := range results {
		ovalroot := oval.Root{}
		if err = xml.Unmarshal(r.Body, &ovalroot); err != nil {
			log.Errorf("Failed to unmarshal. url: %s, err: %s", r.URL, err)
			return subcommands.ExitUsageError
		}
		log.Infof("Fetched: %s", r.URL)
		log.Infof("  %d OVAL definitions", len(ovalroot.Definitions.Definitions))

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
			if err := driver.InsertOval(&root, fmeta); err != nil {
				log.Error(err)
				return subcommands.ExitFailure
			}
		}
		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}
