package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vulsio/goval-dictionary/commands"
	"github.com/vulsio/goval-dictionary/config"
)

// Name ... Name
const Name string = "goval-dictionary"

func main() {
	var v = flag.Bool("v", false, "Show version")

	if envArgs := os.Getenv("GOVAL_DICTIONARY_ARGS"); 0 < len(envArgs) {
		commands.RootCmd.SetArgs(strings.Fields(envArgs))
	} else {
		flag.Parse()
	}

	if *v {
		fmt.Printf("goval-dictionary %s %s\n", config.Version, config.Revision)
		os.Exit(0)
	}

	if err := commands.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
