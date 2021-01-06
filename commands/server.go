package commands

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	server "github.com/kotakanbe/goval-dictionary/server"
	"github.com/kotakanbe/goval-dictionary/util"
)

// ServerCmd is Subcommand for OVAL dictionary HTTP Server
type ServerCmd struct {
	logDir  string
	logJSON bool
}

// Name return subcommand name
func (*ServerCmd) Name() string { return "server" }

// Synopsis return synopsis
func (*ServerCmd) Synopsis() string { return "Start OVAL dictionary HTTP server" }

// Usage return usage
func (*ServerCmd) Usage() string {
	return `server:
	server
		[-bind=127.0.0.1]
		[-port=8000]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-dbtype=mysql|sqlite3]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-log-dir=/path/to/log]
		[-log-json]

`
}

// SetFlags set flag
func (p *ServerCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode (default: false)")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode (default: false)")
	f.BoolVar(&c.Conf.Quiet, "quiet", false, "quiet mode (no output)")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.logDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&p.logJSON, "log-json", false, "output log as JSON")

	pwd := os.Getenv("PWD")
	f.StringVar(&c.Conf.DBPath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&c.Conf.DBType, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3 or mysql supported)")

	f.StringVar(&c.Conf.Bind,
		"bind",
		"127.0.0.1",
		"HTTP server bind to IP address (default: loop back interface)")
	f.StringVar(&c.Conf.Port, "port", "1324",
		"HTTP server port number")
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.SetLogger(p.logDir, c.Conf.Quiet, c.Conf.Debug, p.logJSON)
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	log15.Info("Starting HTTP Server...")
	if err := server.Start(p.logDir); err != nil {
		log15.Error("Failed to start server", "err", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
