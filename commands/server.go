package commands

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	log "github.com/kotakanbe/goval-dictionary/log"
	server "github.com/kotakanbe/goval-dictionary/server"
	"github.com/kotakanbe/goval-dictionary/util"
)

// ServerCmd is Subcommand for OVAL dictionary HTTP Server
type ServerCmd struct {
	debug    bool
	debugSQL bool
	logDir   string

	dbpath string
	dbtype string
	bind   string
	port   string
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
		[-dbpath=$PWD/cve.sqlite3 or connection string]
		[-dbtype=mysql|sqlite3]
		[-debug]
		[-debug-sql]
		[-log-dir=/path/to/log]

`
}

// SetFlags set flag
func (p *ServerCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debug, "debug", false,
		"debug mode (default: false)")
	f.BoolVar(&p.debugSQL, "debug-sql", false,
		"SQL debug mode (default: false)")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.logDir, "log-dir", defaultLogDir, "/path/to/log")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.dbpath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&p.dbtype, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3 or mysql supported)")

	f.StringVar(&p.bind,
		"bind",
		"127.0.0.1",
		"HTTP server bind to IP address (default: loop back interface)")
	f.StringVar(&p.port, "port", "1324",
		"HTTP server port number")
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	log.Initialize(p.logDir)

	c.Conf.DebugSQL = p.debugSQL
	c.Conf.Debug = p.debug
	if c.Conf.Debug {
		log.SetDebug()
	}

	c.Conf.Bind = p.bind
	c.Conf.Port = p.port
	c.Conf.DBPath = p.dbpath
	c.Conf.DBType = p.dbtype

	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	log.Infof("Opening DB (%s).", c.Conf.DBType)
	if err := db.OpenDB(); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	log.Info("Starting HTTP Server...")
	if err := server.Start(p.logDir); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
