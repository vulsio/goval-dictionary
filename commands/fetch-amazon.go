package commands

import (
	"context"
	"encoding/xml"
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
	LogDir    string
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
		[-log-dir=/path/to/log]

	$ goval-dictionary fetch-amazon
`
}

// SetFlags set flag
func (p *FetchAmazonCmd) SetFlags(f *flag.FlagSet) {
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
func (p *FetchAmazonCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Quiet = p.Quiet
	c.Conf.DebugSQL = p.DebugSQL
	c.Conf.Debug = p.Debug
	c.Conf.DBPath = p.DBPath
	c.Conf.DBType = p.DBType
	c.Conf.HTTPProxy = p.HTTPProxy

	util.SetLogger(p.LogDir, c.Conf.Quiet, c.Conf.Debug)
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	result, err := fetcher.FetchAmazonFile()
	if err != nil {
		log15.Error("Failed to fetch files.", "err", err)
		return subcommands.ExitFailure
	}

	amazonRSS := models.AmazonRSS{}
	if err = xml.Unmarshal(result.Body, &amazonRSS); err != nil {
		log15.Error("Failed to unmarshal.", "url", result.URL, "err", err)
		return subcommands.ExitUsageError
	}
	defs := models.ConvertAmazonToModel(&amazonRSS)

	var driver db.DB
	if driver, err = db.NewDB(c.Amazon, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL); err != nil {
		log15.Error("Failed to new db.", "err", err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	root := models.Root{
		Family:      c.Amazon,
		OSVersion:   "0",
		Definitions: defs,
		Timestamp:   time.Now(),
	}

	log15.Info(fmt.Sprintf("%d CVEs", len(defs)))
	if err := driver.InsertOval(&root, models.FetchMeta{}); err != nil {
		log15.Error("Failed to insert meta.", "err", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
