package commands

import (
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
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
	"github.com/ymomoi/goval-parser/oval"
)

// FetchDebianCmd is Subcommand for fetch RedHat OVAL
type FetchDebianCmd struct {
	last2Y    bool
	years     bool
	ovalFiles bool
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
		[-oval-files]

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
		"Refresh oval data in the last two years.")

	f.BoolVar(&p.years, "years", false,
		"Refresh oval data of specific years.")

	f.BoolVar(&p.ovalFiles, "oval-files", false,
		"Refresh oval data from local files.")

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

	roots := []oval.Root{}
	switch {
	case p.last2Y || p.years:
		var err error
		if roots, err = p.fetchFromInternet(f); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	case p.ovalFiles:
		var err error
		if roots, err = p.fetchFromFiles(f); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
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

	for _, r := range roots {
		log.Infof("Fetched %d OVAL definitions", len(r.Definitions.Definitions))

		var timeformat = "2006-01-02T15:04:05.999-07:00"
		t, err := time.Parse(timeformat, r.Generator.Timestamp)
		if err != nil {
			panic(err)
		}

		metas := models.ConvertDebianToModel(&r)
		for _, m := range metas {
			m.Timestamp = t
			if err := db.InsertDebian(m); err != nil {
				log.Error(err)
				return subcommands.ExitFailure
			}
		}
	}

	return subcommands.ExitSuccess
}

func (p *FetchDebianCmd) fetchFromInternet(f *flag.FlagSet) (roots []oval.Root, err error) {
	years := []int{}
	thisYear := time.Now().Year()
	switch {
	case p.last2Y:
		for i := 0; i < 2; i++ {
			years = append(years, thisYear-i)
		}
	case p.years:
		if len(f.Args()) == 0 {
			return nil,
				fmt.Errorf("Specify years to fetch (from 1999 to %d)", thisYear)
		}
		for _, arg := range f.Args() {
			year, err := strconv.Atoi(arg)
			if err != nil || year < 1999 || time.Now().Year() < year {
				return nil,
					fmt.Errorf("Specify years to fetch (from 1999 to %d), arg: %s",
						thisYear, arg)
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
		return nil, fmt.Errorf("specify -last2y or -years")
	}

	results, err := fetcher.FetchDebianFiles(years)
	if err != nil {
		return nil, err
	}

	for _, r := range results {
		roots = append(roots, *r.Root)
	}
	return
}

func (p *FetchDebianCmd) fetchFromFiles(f *flag.FlagSet) (roots []oval.Root, err error) {
	if len(f.Args()) == 0 {
		return nil,
			fmt.Errorf("Specify OVAL file paths to read")
	}
	for _, arg := range f.Args() {
		data, err := ioutil.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		var root oval.Root
		if err := xml.Unmarshal([]byte(data), &root); err != nil {
			return nil, err
		}
		roots = append(roots, root)
	}
	return
}
