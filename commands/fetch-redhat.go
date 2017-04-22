package commands

import (
	"context"
	"flag"
	"os"
	"strconv"
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

// FetchRedHatCmd is Subcommand for fetch RedHat OVAL
type FetchRedHatCmd struct {
	Debug     bool
	DebugSQL  bool
	LogDir    string
	DBPath    string
	DBType    string
	HTTPProxy string
}

// Name return subcommand name
func (*FetchRedHatCmd) Name() string { return "fetch-redhat" }

// Synopsis return synopsis
func (*FetchRedHatCmd) Synopsis() string { return "Fetch Vulnerability dictionary from RedHat" }

// Usage return usage
func (*FetchRedHatCmd) Usage() string {
	return `fetch-redhat:
	fetch-redhat
		[-dbtype=mysql|sqlite3]
		[-dbpath=$PWD/cve.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
   $ for i in {5..7}; do goval-dictionary fetch-redhat $i; done
`
}

// SetFlags set flag
func (p *FetchRedHatCmd) SetFlags(f *flag.FlagSet) {
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
		"Database type to store data in (sqlite3 or mysql supported)")

	f.StringVar(
		&p.HTTPProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)
}

// Execute execute
func (p *FetchRedHatCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
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
		ver, err := strconv.Atoi(arg)
		if err != nil || ver < 5 {
			log.Errorf("Specify version to fetch (from 5 to latest RHEL version), arg: %s", arg)
			return subcommands.ExitUsageError
		}
		vers = append(vers, arg)
	}

	results, err := fetcher.FetchRedHatFiles(vers)
	if err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	log.Infof("Opening DB (%s).", c.Conf.DBType)
	if err := db.OpenDB(); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	log.Info("Migrating DB")
	if err := db.MigrateDB(); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	red := db.NewRedHat()
	for _, r := range results {
		log.Infof("Fetched: %s", r.URL)
		log.Infof("  %d OVAL definitions", len(r.Root.Definitions.Definitions))
		defs := models.ConvertRedHatToModel(r.Root)

		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, r.Root.Generator.Timestamp)
		if err != nil {
			panic(err)
		}

		root := models.Root{
			Family:      c.RedHat,
			Release:     r.Target,
			Definitions: defs,
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		if err := red.InsertOval(&root, fmeta); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
		if err := red.InsertFetchMeta(fmeta); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}
