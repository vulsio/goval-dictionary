package commands

import (
	"context"
	"encoding/xml"
	"flag"
	"io/ioutil"
	"os"
	"time"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
)

// FetchAmazonCmd is Subcommand for fetch Alpine secdb
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

	result, err := fetcher.FetchAmazonFile()
	if err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	amazonRSS := models.AmazonRSS{}
	if err = xml.Unmarshal(result.Body, &amazonRSS); err != nil {
		log.Errorf("Failed to unmarshal. err: %s", err)
		return subcommands.ExitUsageError
	}
	defs := models.ConvertAmazonToModel(&amazonRSS)

	var driver db.DB
	if driver, err = db.NewDB(c.Amazon, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	root := models.Root{
		Family:      c.Amazon,
		Definitions: defs,
		Timestamp:   time.Now(),
	}

	log.Infof("  %d CVEs", len(defs))
	if err := driver.InsertOval(&root, models.FetchMeta{}); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
