package commands

import (
	"context"
	"flag"
	"os"
	"strconv"
	"time"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
)

// FetchDebianCmd is Subcommand for fetch RedHat OVAL
type FetchDebianCmd struct {
	last2Y    bool
	years     bool
	Debug     bool
	DebugSQL  bool
	LogDir    string
	DBPath    string
	DBType    string
	HTTPProxy string
}

// Name return subcommand name
func (*FetchDebianCmd) Name() string { return "fetch-debian" }

// Synopsis return synopsis
func (*FetchDebianCmd) Synopsis() string { return "Fetch Vulnerability dictionary from Debian" }

// Usage return usage
func (*FetchDebianCmd) Usage() string {
	return `fetch-debian:
	fetch-debian
		[-last2y]
		[-years] 2015 2016 ...
		[-dbtype=mysql|sqlite3]
		[-dbpath=$PWD/cve.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
   $ for i in {1999..2017}; do goval-dictionary fetch-debian $i; done
`
}

// SetFlags set flag
func (p *FetchDebianCmd) SetFlags(f *flag.FlagSet) {
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

	f.BoolVar(&p.last2Y, "last2y", false,
		"Refresh NVD data in the last two years.")

	f.BoolVar(&p.years, "years", false,
		"Refresh NVD data of specific years.")

	f.StringVar(
		&p.HTTPProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)
}

// Execute execute
func (p *FetchDebianCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
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

	years := []int{}
	thisYear := time.Now().Year()

	switch {
	case p.last2Y:
		for i := 0; i < 2; i++ {
			years = append(years, thisYear-i)
		}
	case p.years:
		if len(f.Args()) == 0 {
			log.Errorf("Specify years to fetch (from 1999 to %d)", thisYear)
			return subcommands.ExitUsageError
		}
		for _, arg := range f.Args() {
			year, err := strconv.Atoi(arg)
			if err != nil || year < 1999 || time.Now().Year() < year {
				log.Errorf("Specify years to fetch (from 1999 to %d), arg: %s", thisYear, arg)
				return subcommands.ExitUsageError
			}
			found := false
			for _, y := range years {
				if y == year {
					found = true
					break
				}
			}
			if !found {
				years = append(years, year)
			}
		}
	default:
		log.Errorf("specify -last2y or -years")
		return subcommands.ExitUsageError
	}

	results, err := fetcher.FetchDebianFiles(years)
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

	for _, r := range results {
		log.Infof("Fetched %d OVAL definitions", len(r.Root.Definitions.Definitions))

		var timeformat = "2006-01-02T15:04:05.999-07:00"
		t, err := time.Parse(timeformat, r.Root.Generator.Timestamp)
		if err != nil {
			panic(err)
		}

		metas := models.ConvertDebianToModel(r.Root)
		for _, m := range metas {
			m.Timestamp = t
		}

		//  if err := db.InsertRedHat(); err != nil {
		//      log.Error(err)
		//      return subcommands.ExitFailure
		//  }
	}

	return subcommands.ExitSuccess
}
