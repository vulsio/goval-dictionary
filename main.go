package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/subcommands"
	"github.com/kotakanbe/goval-dictionary/commands"
)

// Name ... Name
const Name string = "goval-dictionary"

// Version ... Version
var version = "0.0.2"

// Revision of Git
var revision string

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&commands.FetchRedHatCmd{}, "fetch-redhat")
	subcommands.Register(&commands.FetchDebianCmd{}, "fetch-debian")
	subcommands.Register(&commands.FetchUbuntuCmd{}, "fetch-ubuntu")
	subcommands.Register(&commands.FetchSUSECmd{}, "fetch-suse")
	subcommands.Register(&commands.FetchOracleCmd{}, "fetch-oracle")
	subcommands.Register(&commands.FetchAlpineCmd{}, "fetch-alpine")
	subcommands.Register(&commands.SelectCmd{}, "select")
	subcommands.Register(&commands.ServerCmd{}, "server")

	var v = flag.Bool("v", false, "Show version")

	if envArgs := os.Getenv("GOVAL_DICTIONARY_ARGS"); 0 < len(envArgs) {
		flag.CommandLine.Parse(strings.Fields(envArgs))
	} else {
		flag.Parse()
	}

	if *v {
		fmt.Printf("goval-dictionary %s %s\n", version, revision)
		os.Exit(int(subcommands.ExitSuccess))
	}

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
