package commands

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/log"
)

// SelectRedHatCmd is Subcommand for fetch RedHat OVAL
type SelectRedHatCmd struct {
	DebugSQL bool
	DBPath   string
	DBType   string
	LogDir   string
}

// Name return subcommand name
func (*SelectRedHatCmd) Name() string { return "select-redhat" }

// Synopsis return synopsis
func (*SelectRedHatCmd) Synopsis() string { return "Select from RedHat OVAL" }

// Usage return usage
func (*SelectRedHatCmd) Usage() string {
	return `fetch-redhat:
	fetch-redhat
		[-dbtype=mysql|sqlite3]
		[-dbpath=$PWD/cve.sqlite3 or connection string]
		[-debug-sql]
		[-log-dir=/path/to/log]
	`
}

// SetFlags set flag
func (p *SelectRedHatCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.DebugSQL, "debug-sql", false,
		"SQL debug mode")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.DBPath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&p.DBType, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3 or mysql supported)")
}

// Execute execute
func (p *SelectRedHatCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
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

	log.Info("Migrating DB")
	if err := db.MigrateDB(); err != nil {
		log.Fatal(err)
	}

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
	return subcommands.ExitSuccess
}
