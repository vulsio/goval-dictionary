package commands

import (
	"context"
	"flag"
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
)

// FetchUbuntuCmd is Subcommand for fetch RedHat OVAL
type FetchUbuntuCmd struct {
	Debug     bool
	DebugSQL  bool
	LogDir    string
	DBPath    string
	DBType    string
	HTTPProxy string
}

// Name return subcommand name
func (*FetchUbuntuCmd) Name() string { return "fetch-ubuntu" }

// Synopsis return synopsis
func (*FetchUbuntuCmd) Synopsis() string { return "Fetch Vulnerability dictionary from Ubuntu" }

// Usage return usage
func (*FetchUbuntuCmd) Usage() string {
	return `fetch-ubuntu:
	fetch-ubuntu
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/cve.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
   $ goval-dictionary fetch-ubuntu 12 14 16
`
}

// SetFlags set flag
func (p *FetchUbuntuCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.Debug, "debug", false,
		"debug mode")
	f.BoolVar(&p.DebugSQL, "debug-sql", false,
		"SQL debug mode")

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
func (p *FetchUbuntuCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	log.Initialize(p.LogDir)

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

	vers := []string{}
	if len(f.Args()) == 0 {
		log.Errorf("Specify versions to fetch")
		return subcommands.ExitUsageError
	}
	for _, arg := range f.Args() {
		vers = append(vers, arg)
	}

	results, err := fetcher.FetchUbuntuFiles(vers)
	if err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	var driver db.DB
	if driver, err = db.NewDB(c.Debian, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	for _, r := range results {
		log.Infof("Fetched: %s", r.URL)
		log.Infof("  %d OVAL definitions", len(r.Root.Definitions.Definitions))

		defs := models.ConvertUbuntuToModel(r.Root)

		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, r.Root.Generator.Timestamp)
		if err != nil {
			panic(err)
		}

		root := models.Root{
			Family:      c.Ubuntu,
			OSVersion:   r.Target,
			Definitions: defs,
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		if err := driver.InsertOval(&root, fmeta); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}
