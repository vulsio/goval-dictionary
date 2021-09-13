package commands

import (
	"fmt"

	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Long:  `Show version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("goval-dictionary %s %s\n", config.Version, config.Revision)
	},
}
