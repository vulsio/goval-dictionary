package commands

import (
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
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
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/cve.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-log-dir=/path/to/log]
		[-oval-files]

For the first time, run the blow command to fetch data for all versions.
   $ for i in {1999..2017}; do goval-dictionary fetch-debian -years $i; done
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
		"Database type to store data in (sqlite3, mysql, postgres or redis supported)")

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

	var err error
	results := []fetcher.FetchResult{}
	switch {
	case p.last2Y || p.years:
		if results, err = p.fetchFromInternet(f); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	case p.ovalFiles:
		if results, err = p.fetchFromFiles(f); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
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

		//  var timeformat = "2006-01-02T15:04:05.999-07:00"
		var timeformat = "2006-01-02T15:04:05"
		var t time.Time
		t, err = time.Parse(timeformat, strings.Split(r.Root.Generator.Timestamp, ".")[0])
		if err != nil {
			panic(err)
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		roots := models.ConvertDebianToModel(r.Root)
		for _, root := range roots {
			root.Timestamp = t
			if err = driver.InsertOval(&root, fmeta); err != nil {
				log.Error(err)
				return subcommands.ExitFailure
			}
		}
		if err = driver.InsertFetchMeta(fmeta); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}

func (p *FetchDebianCmd) fetchFromInternet(f *flag.FlagSet) ([]fetcher.FetchResult, error) {
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

	return fetcher.FetchDebianFiles(years)
}

func (p *FetchDebianCmd) fetchFromFiles(f *flag.FlagSet) (res []fetcher.FetchResult, err error) {
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
		res = append(res, fetcher.FetchResult{
			URL:  arg,
			Root: &root,
		})
	}
	return
}
