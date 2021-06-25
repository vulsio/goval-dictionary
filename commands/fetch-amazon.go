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
	LogDir  string
	LogJSON bool
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
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&c.Conf.Quiet, "quiet", false, "quiet mode (no output)")
	f.BoolVar(&c.Conf.NoDetails, "no-details", false, "without vulnerability details")

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
func (p *FetchAmazonCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.SetLogger(p.LogDir, c.Conf.Quiet, c.Conf.Debug, p.LogJSON)
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	uinfo, err := fetcher.FetchUpdateInfoAmazonLinux1()
	if err != nil {
		log15.Error("Failed to fetch updateinfo for Amazon Linux1", "err", err)
		return subcommands.ExitFailure
	}
	root := models.Root{
		Family:      c.Amazon,
		OSVersion:   "1",
		Definitions: models.ConvertAmazonToModel(uinfo),
		Timestamp:   time.Now(),
	}
	log15.Info(fmt.Sprintf("%d CVEs for Amazon Linux1. Inserting to DB", len(root.Definitions)))
	if err := execute(&root); err != nil {
		log15.Error("Failed to Insert Amazon1", "err", err)
		return subcommands.ExitSuccess
	}

	uinfo, err = fetcher.FetchUpdateInfoAmazonLinux2()
	if err != nil {
		log15.Error("Failed to fetch updateinfo for Amazon Linux2", "err", err)
		return subcommands.ExitFailure
	}
	root = models.Root{
		Family:      c.Amazon,
		OSVersion:   "2",
		Definitions: models.ConvertAmazonToModel(uinfo),
		Timestamp:   time.Now(),
	}
	log15.Info(fmt.Sprintf("%d CVEs for Amazon Linux2. Inserting to DB", len(root.Definitions)))
	if err := execute(&root); err != nil {
		log15.Error("Failed to Insert Amazon2", "err", err)
		return subcommands.ExitSuccess
	}
	return subcommands.ExitSuccess
}

func execute(root *models.Root) error {
	driver, locked, err := db.NewDB(c.Amazon, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL)
	if err != nil {
		if locked {
			return fmt.Errorf("Failed to open DB. Close DB connection before fetching: %w", err)
		}
		return fmt.Errorf("Failed to open DB: %w", err)
	}
	defer func() {
		err := driver.CloseDB()
		if err != nil {
			log15.Error("Failed to close DB", "err", err)
		}
	}()

	fmeta := models.FetchMeta{
		Timestamp: time.Now(),
		FileName:  fmt.Sprintf("FetchUpdateInfoAmazonLinux%s", root.OSVersion),
	}

	if err := driver.InsertOval(c.Amazon, root, fmeta); err != nil {
		return fmt.Errorf("Failed to insert OVAL: %w", err)
	}
	if err := driver.InsertFetchMeta(fmeta); err != nil {
		log15.Error("Failed to insert meta", "err", err)
		return fmt.Errorf("Failed to insert FetchMeta: %w", err)
	}
	log15.Info("Finish", "Updated", len(root.Definitions))
	return nil
}
