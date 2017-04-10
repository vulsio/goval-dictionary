package commands

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/util"
)

// SelectCmd is Subcommand for fetch RedHat OVAL
type SelectCmd struct {
	DebugSQL bool
	DBPath   string
	DBType   string
	LogDir   string

	ByPackage bool
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
		[-dbpath=$PWD/cve.sqlite3 or connection string]
		[-debug-sql]
		[-log-dir=/path/to/log]

		[-by-package]
	`
}

// SetFlags set flag
func (p *SelectCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.DebugSQL, "debug-sql", false,
		"SQL debug mode")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.DBPath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&p.DBType, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3 or mysql supported)")

	f.BoolVar(&p.ByPackage, "by-package", true, "select OVAL by package name")
}

// Execute execute
func (p *SelectCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.DebugSQL = p.DebugSQL
	c.Conf.DBPath = p.DBPath
	c.Conf.DBType = p.DBType

	log.Initialize(p.LogDir)

	if f.NArg() != 3 {
		log.Fatal("./goval-dictionary select-redhat RedHat 7 java-1.7.0-openjdk")
	}

	log.Infof("Opening DB (%s).", c.Conf.DBType)
	if err := db.OpenDB(); err != nil {
		log.Fatal(err)
	}

	if p.ByPackage {
		dfs, err := db.Get(f.Args()[0], f.Args()[1], f.Args()[2])
		if err != nil {
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

	return subcommands.ExitSuccess
}
