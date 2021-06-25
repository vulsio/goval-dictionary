package commands

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
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
	LogDir  string
	LogJSON bool
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
	$ goval-dictionary fetch-alpine 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11

`
}

// SetFlags set flag
func (p *FetchAlpineCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&c.Conf.Quiet, "quiet", false, "quiet mode (no output)")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&p.LogJSON, "log-json", false, "output log as JSON")

	pwd := os.Getenv("PWD")
	f.StringVar(&c.Conf.DBPath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&c.Conf.DBType, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3, mysql, postgres or redis supported)")

	f.StringVar(
		&c.Conf.HTTPProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)
}

// Execute execute
func (p *FetchAlpineCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
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
	defer func() {
		_ = driver.CloseDB()
	}()

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
			ss := strings.Split(r.URL, "/")
			m[r.Target] = T{
				url:  strings.Join(ss[len(ss)-3:len(ss)-1], "/"),
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

		fmeta := models.FetchMeta{
			Timestamp: time.Now(),
			FileName:  t.url,
		}

		log15.Info(fmt.Sprintf("%d CVEs", len(t.defs)))
		if err := driver.InsertOval(c.Alpine, &root, fmeta); err != nil {
			log15.Error("Failed to insert meta.", "err", err)
			return subcommands.ExitFailure
		}
		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log15.Error("Failed to insert meta", "err", err)
			return subcommands.ExitFailure
		}
		log15.Info("Finish", "Updated", len(root.Definitions))
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
