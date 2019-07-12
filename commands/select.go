package commands

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"github.com/inconshreveable/log15"
	"github.com/k0kubun/pp"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
)

// SelectCmd is Subcommand for fetch RedHat OVAL
type SelectCmd struct {
	DebugSQL bool
	DBPath   string
	DBType   string
	Quiet    bool
	LogDir   string
	LogJSON  bool

	ByPackage bool
	ByCveID   bool
}

// Name return subcommand name
func (*SelectCmd) Name() string { return "select" }

// Synopsis return synopsis
func (*SelectCmd) Synopsis() string { return "Select from DB" }

// Usage return usage
func (*SelectCmd) Usage() string {
	return `select:
	select
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-debug-sql]
		[-quiet]
		[-log-dir=/path/to/log]
		[-log-json]

		[-by-package] amazon 2 bind x86_64
		[-by-cveid] redhat 7 CVE-2017-6009

`
}

// SetFlags set flag
func (p *SelectCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&p.Quiet, "quiet", false, "quiet mode (no output)")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&p.LogJSON, "log-json", false, "output log as JSON")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.DBPath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&p.DBType, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3 or mysql supported)")

	f.BoolVar(&p.ByPackage, "by-package", false, "select OVAL by package name")
	f.BoolVar(&p.ByCveID, "by-cveid", false, "select OVAL by CVE-ID")
}

// Execute execute
func (p *SelectCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.DebugSQL = p.DebugSQL
	c.Conf.DBPath = p.DBPath
	c.Conf.DBType = p.DBType

	util.SetLogger(p.LogDir, c.Conf.Quiet, c.Conf.Debug, p.LogJSON)
	if f.NArg() != 3 {
		log15.Crit(`
		Usage:
		select OVAL by package name
		./goval-dictionary select -by-package RedHat 7 java-1.7.0-openjdk x86_64

		select OVAL by CVE-ID
		./goval-dictionary select -by-cveid RedHat 7 CVE-2015-1111
		`)
	}

	if !p.ByPackage && !p.ByCveID {
		log15.Crit("Specify -by-package or -by-cveid")
	}

	var err error
	var driver db.DB
	driver, locked, err := db.NewDB(f.Args()[0], c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL)
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before select", "err", err)
			return subcommands.ExitFailure
		}
		log15.Error("Failed to open DB", "err", err)
		return subcommands.ExitFailure
	}

	// count, err := driver.CountDefs("redhat", "7")
	// pp.Println("count: ", count, err)

	var dfs []models.Definition
	if p.ByPackage {
		dfs, err = driver.GetByPackName(f.Args()[0], f.Args()[1], f.Args()[2], f.Args()[3])
		if err != nil {
			//TODO Logger
			log15.Crit("Failed to get cve by package.", "err", err)
		}

		for _, d := range dfs {
			for _, cve := range d.Advisory.Cves {
				fmt.Printf("%s\n", cve.CveID)
				for _, pack := range d.AffectedPacks {
					fmt.Printf("    %v\n", pack)
				}
			}
		}
		fmt.Println("------------------")
		pp.Println(dfs)
		return subcommands.ExitSuccess
	}

	return subcommands.ExitSuccess
}
