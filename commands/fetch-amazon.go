package commands

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/subcommands"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
)

// FetchAmazonCmd is Subcommand for fetch Amazon ALAS RSS
// https://alas.aws.amazon.com/alas.rss
type FetchAmazonCmd struct {
	Debug     bool
	DebugSQL  bool
	Quiet     bool
	NoDetails bool
	LogDir    string
	LogJSON   bool
	DBPath    string
	DBType    string
	HTTPProxy string
}

// Name return subcommand name
func (*FetchAmazonCmd) Name() string { return "fetch-amazon" }

// Synopsis return synopsis
func (*FetchAmazonCmd) Synopsis() string { return "Fetch Vulnerability dictionary from Amazon ALAS" }

// Usage return usage
func (*FetchAmazonCmd) Usage() string {
	return `fetch-amazon:
	fetch-amazon
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-no-details]
		[-log-dir=/path/to/log]
		[-log-json]

	$ goval-dictionary fetch-amazon
`
}

// SetFlags set flag
func (p *FetchAmazonCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.Debug, "debug", false, "debug mode")
	f.BoolVar(&p.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&p.Quiet, "quiet", false, "quiet mode (no output)")
	f.BoolVar(&p.NoDetails, "no-details", false, "without vulnerability details")

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
func (p *FetchAmazonCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Quiet = p.Quiet
	c.Conf.DebugSQL = p.DebugSQL
	c.Conf.Debug = p.Debug
	c.Conf.DBPath = p.DBPath
	c.Conf.DBType = p.DBType
	c.Conf.HTTPProxy = p.HTTPProxy
	c.Conf.NoDetails = p.NoDetails

	util.SetLogger(p.LogDir, c.Conf.Quiet, c.Conf.Debug, p.LogJSON)
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	uinfo, err := fetcher.FetchUpdateInfoAmazonLinux1()
	if err != nil {
		log15.Error("Failed to fetch updateinfo for Amazon Linux1", "err", err)
		return subcommands.ExitFailure
	}
	defs := models.ConvertAmazonToModel(uinfo)
	root := models.Root{
		Family:      c.Amazon,
		OSVersion:   "1",
		Definitions: defs,
		Timestamp:   time.Now(),
	}
	log15.Info(fmt.Sprintf("%d CVEs for Amazon Linux1. Inserting to DB", len(defs)))
	driver, locked, err := db.NewDB(c.Amazon, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL)
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return subcommands.ExitFailure
		}
		log15.Error("Failed to open DB", "err", err)
		return subcommands.ExitFailure
	}
	if err := driver.InsertOval(c.Amazon, &root, models.FetchMeta{}); err != nil {
		log15.Error("Failed to insert OVAL", "err", err)
		return subcommands.ExitFailure
	}
	log15.Info("Success")
	if err := driver.CloseDB(); err != nil {
		log15.Crit("Failed to close DB", "err", err)
		return subcommands.ExitFailure
	}

	uinfo, err = fetcher.FetchUpdateInfoAmazonLinux2()
	if err != nil {
		log15.Error("Failed to fetch updateinfo for Amazon Linux2", "err", err)
		return subcommands.ExitFailure
	}
	defs = models.ConvertAmazonToModel(uinfo)
	root = models.Root{
		Family:      c.Amazon,
		OSVersion:   "2",
		Definitions: defs,
		Timestamp:   time.Now(),
	}
	log15.Info(fmt.Sprintf("%d CVEs for Amazon Linux2. Inserting to DB", len(defs)))
	driver2, locked, err := db.NewDB(c.Amazon, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL)
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return subcommands.ExitFailure
		}
		log15.Error("Failed to open DB", "err", err)
		return subcommands.ExitFailure
	}
	defer func() {
		err := driver2.CloseDB()
		if err != nil {
			log15.Crit("Failed to close DB", "err", err)
		}
	}()
	if err := driver2.InsertOval(c.Amazon, &root, models.FetchMeta{}); err != nil {
		log15.Error("Failed to insert OVAL", "err", err)
		return subcommands.ExitFailure
	}
	log15.Info("Success")

	return subcommands.ExitSuccess
}
