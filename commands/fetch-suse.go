package commands

import (
	"context"
	"encoding/xml"
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/ymomoi/goval-parser/oval"
)

// FetchSUSECmd is Subcommand for fetch SUSE OVAL
type FetchSUSECmd struct {
	OpenSUSE              bool
	OpenSUSELeap          bool
	SUSEEnterpriseServer  bool
	SUSEEnterpriseDesktop bool
	SUSEOpenstackCloud    bool
	Debug                 bool
	DebugSQL              bool
	Quiet                 bool
	LogDir                string
	DBPath                string
	DBType                string
	HTTPProxy             string
	OVALPath              string
}

// Name return subcommand name
func (*FetchSUSECmd) Name() string { return "fetch-suse" }

// Synopsis return synopsis
func (*FetchSUSECmd) Synopsis() string { return "Fetch Vulnerability dictionary from SUSE" }

// Usage return usage
func (*FetchSUSECmd) Usage() string {
	return `fetch-suse:
	fetch-suse
		[-opensuse]
		[-opensuse-leap]
		[-suse-enterprise-server]
		[-suse-enterprise-desktop]
		[-suse-openstack-cloud]
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-log-dir=/path/to/log]

For details, see https://github.com/kotakanbe/goval-dictionary#usage-fetch-oval-data-from-suse
	$ goval-dictionary fetch-suse -opensuse 13.2

`
}

// SetFlags set flag
func (p *FetchSUSECmd) SetFlags(f *flag.FlagSet) {

	f.BoolVar(&p.OpenSUSE, "opensuse", false, "OpenSUSE")
	f.BoolVar(&p.OpenSUSELeap, "opensuse-leap", false, "OpenSUSE Leap")
	f.BoolVar(&p.SUSEEnterpriseServer, "suse-enterprise-server", false, "SUSE Enterprise Server")
	f.BoolVar(&p.SUSEEnterpriseDesktop, "suse-enterprise-desktop", false, "SUSE Enterprise Desktop")
	f.BoolVar(&p.SUSEOpenstackCloud, "suse-openstack-cloud", false, "SUSE Openstack cloud")

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

	f.StringVar(&p.HTTPProxy, "http-proxy", "", "http://proxy-url:port (default: empty)")

	f.StringVar(&p.OVALPath, "oval-path", "", "Local file path of Downloaded oval")
}

// Execute execute
func (p *FetchSUSECmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
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
		log.Errorf("Specify versions to fetch. Oval files are here: http://ftp.suse.com/pub/projects/security/oval/")
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

	suseType := ""
	switch {
	case p.OpenSUSE:
		suseType = c.OpenSUSE
	case p.OpenSUSELeap:
		suseType = c.OpenSUSELeap
	case p.SUSEEnterpriseServer:
		suseType = c.SUSEEnterpriseServer
	case p.SUSEEnterpriseDesktop:
		suseType = c.SUSEEnterpriseDesktop
	case p.SUSEOpenstackCloud:
		suseType = c.SUSEOpenstackCloud
	}

	var results []fetcher.FetchResult
	var err error
	if p.OVALPath == "" {
		results, err = fetcher.FetchSUSEFiles(suseType, vers)
		if err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	} else {
		dat, err := ioutil.ReadFile(p.OVALPath)
		if err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
		results = []fetcher.FetchResult{{
			Body:   dat,
			Target: vers[0],
		}}
	}

	var driver db.DB
	if driver, err = db.NewDB(suseType, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	defer driver.CloseDB()

	for _, r := range results {
		ovalroot := oval.Root{}
		if err = xml.Unmarshal(r.Body, &ovalroot); err != nil {
			log.Errorf("Failed to unmarshal. url: %s, err: %s", r.URL, err)
			return subcommands.ExitUsageError
		}
		log.Infof("Fetched: %s", r.URL)
		log.Infof("  %d OVAL definitions", len(ovalroot.Definitions.Definitions))

		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, ovalroot.Generator.Timestamp)
		if err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		roots := models.ConvertSUSEToModel(&ovalroot, suseType)
		for _, root := range roots {
			root.Timestamp = time.Now()
			if err := driver.InsertOval(&root, fmeta); err != nil {
				log.Error(err)
				return subcommands.ExitFailure
			}
		}

		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}
