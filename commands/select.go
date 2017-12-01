package commands

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/log"
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

	ByPackage bool
	ByCveID   bool
}

// Name return subcommand name
func (*SelectCmd) Name() string { return "select" }

// Synopsis return synopsis
func (*SelectCmd) Synopsis() string { return "Select from DB" }

// Usage return usage
func (*SelectCmd) Usage() string {
	return `fetch-redhat:
	fetch-redhat
		[-dbtype=mysql|sqlite3]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-debug-sql]
		[-quiet]
		[-log-dir=/path/to/log]

		[-by-package]
		[-by-cveid]

`
}

// SetFlags set flag
func (p *SelectCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&p.Quiet, "quiet", false, "quiet mode (no output)")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")

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

	c.Conf.Quiet = p.Quiet
	if c.Conf.Quiet {
		log.Initialize(p.LogDir, ioutil.Discard)
	} else {
		log.Initialize(p.LogDir, os.Stderr)
	}

	if f.NArg() != 3 {
		log.Fatal(`
		Usage:
		select OVAL by package name
		./goval-dictionary select -by-package RedHat 7 java-1.7.0-openjdk

		select OVAL by CVE-ID
		./goval-dictionary select -by-cveid RedHat 7 CVE-2015-1111
		`)
	}

	if !p.ByPackage && !p.ByCveID {
		log.Fatal("Specify -by-package or -by-cveid")
	}

	var err error
	var driver db.DB
	if driver, err = db.NewDB(f.Args()[0], c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	// count, err := driver.CountDefs("redhat", "7")
	// pp.Println("count: ", count, err)

	var dfs []models.Definition
	if p.ByPackage {
		dfs, err = driver.GetByPackName(f.Args()[1], f.Args()[2])
		if err != nil {
			//TODO Logger
			log.Fatal(err)
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

	if p.ByCveID {
		dfs, err = driver.GetByCveID(f.Args()[1], f.Args()[2])
		if err != nil {
			log.Fatal(err)
		}

		for _, d := range dfs {
			fmt.Printf("%s\n", d.Title)
			fmt.Printf("%s\n", d.Advisory.Severity)
			fmt.Printf("%v\n", d.Advisory.Cves)
		}
		fmt.Println("------------------")
		pp.Println(dfs)
		return subcommands.ExitSuccess
	}

	return subcommands.ExitSuccess
}
