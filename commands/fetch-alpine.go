package commands

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/google/subcommands"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
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
	LogJSON   bool
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
		[-log-json]

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
	f.BoolVar(&p.LogJSON, "log-json", false, "output log as JSON")

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
	c.Conf.DebugSQL = p.DebugSQL
	c.Conf.Debug = p.Debug
	c.Conf.DBPath = p.DBPath
	c.Conf.DBType = p.DBType
	c.Conf.HTTPProxy = p.HTTPProxy

	util.SetLogger(p.LogDir, c.Conf.Quiet, c.Conf.Debug, p.LogJSON)
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	if len(f.Args()) == 0 {
		log15.Error("Specify versions to fetch")
		log15.Error(p.Usage())
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

	driver, locked, err := db.NewDB(c.Alpine, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL)
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return subcommands.ExitFailure
		}
		log15.Error("Failed to open DB", "err", err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	results, err := fetcher.FetchAlpineFiles(vers)
	if err != nil {
		log15.Error("Failed to fetch files", "err", err)
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
			log15.Crit("Failed to unmarshal yml.", "err", err)
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

	for target, t := range m {
		root := models.Root{
			Family:      c.Alpine,
			OSVersion:   target,
			Definitions: t.defs,
			Timestamp:   time.Now(),
		}

		log15.Info(fmt.Sprintf("%d CVEs", len(t.defs)))
		if err := driver.InsertOval(c.Alpine, &root, models.FetchMeta{}); err != nil {
			log15.Error("Failed to insert meta.", "err", err)
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
