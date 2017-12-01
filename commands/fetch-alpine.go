package commands

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
)

// FetchAlpineCmd is Subcommand for fetch Alpine secdb
// https://git.alpinelinux.org/cgit/alpine-secdb/
type FetchAlpineCmd struct {
	Debug     bool
	DebugSQL  bool
	Quiet     bool
	LogDir    string
	DBPath    string
	DBType    string
	HTTPProxy string
}

// Name return subcommand name
func (*FetchAlpineCmd) Name() string { return "fetch-alpine" }

// Synopsis return synopsis
func (*FetchAlpineCmd) Synopsis() string { return "Fetch Vulnerability dictionary from Alpine secdb" }

// Usage return usage
func (*FetchAlpineCmd) Usage() string {
	return `fetch-alpine:
	fetch-alpine
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-log-dir=/path/to/log]

The version list is here https://git.alpinelinux.org/cgit/alpine-secdb/tree/
	$ goval-dictionary fetch-alpine 3.3 3.4 3.5 3.6

`
}

// SetFlags set flag
func (p *FetchAlpineCmd) SetFlags(f *flag.FlagSet) {
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
func (p *FetchAlpineCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
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

	if len(f.Args()) == 0 {
		log.Errorf("Specify versions to fetch.")
		log.Errorf(p.Usage())
		return subcommands.ExitUsageError
	}

	// Distinct
	v := map[string]bool{}
	vers := []string{}
	for _, arg := range f.Args() {
		v[arg] = true
	}
	for k := range v {
		vers = append(vers, k)
	}

	results, err := fetcher.FetchAlpineFiles(vers)
	if err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	// Join community.yaml, main.yaml
	type T struct {
		url  string
		defs []models.Definition
	}
	m := map[string]T{}
	for _, r := range results {
		secdb, err := unmarshalYml(r.Body)
		if err != nil {
			log.Fatal(err)
			return subcommands.ExitFailure
		}

		defs := models.ConvertAlpineToModel(secdb)
		if t, ok := m[r.Target]; ok {
			t.defs = append(t.defs, defs...)
			m[r.Target] = t
		} else {
			m[r.Target] = T{
				defs: defs,
			}
		}
	}

	// pp.Println(m)

	var driver db.DB
	if driver, err = db.NewDB(c.Alpine, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	for target, t := range m {
		root := models.Root{
			Family:      c.Alpine,
			OSVersion:   target,
			Definitions: t.defs,
			Timestamp:   time.Now(),
		}

		log.Infof("  %d CVEs", len(t.defs))
		if err := driver.InsertOval(&root, models.FetchMeta{}); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}

func unmarshalYml(data []byte) (*models.AlpineSecDB, error) {
	t := models.AlpineSecDB{}
	err := yaml.Unmarshal([]byte(data), &t)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal: %s", err)
	}
	return &t, nil
}
