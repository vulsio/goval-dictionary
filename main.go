package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"github.com/kotakanbe/goval-dictionary/commands"
)

// Name ... Name
const Name string = "goval-dictionary"

// Version ... Version
var version = "0.0.1"

// Revision of Git
var revision string

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&commands.FetchRedHatCmd{}, "fetch-redhat")
	subcommands.Register(&commands.FetchDebianCmd{}, "fetch-debian")
	subcommands.Register(&commands.SelectCmd{}, "select")
	subcommands.Register(&commands.ServerCmd{}, "server")

	var v = flag.Bool("v", false, "Show version")

	flag.Parse()

	if *v {
		fmt.Printf("goval-dictionary %s %s\n", version, revision)
		os.Exit(int(subcommands.ExitSuccess))
	}

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
