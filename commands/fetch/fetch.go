package fetch

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// FetchCmd represents the fetch command
var FetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch Vulnerability dictionary",
	Long:  `Fetch Vulnerability dictionary`,
}

func init() {
	// subcommands
	FetchCmd.AddCommand(fetchRedHatCmd)
	FetchCmd.AddCommand(fetchOracleCmd)
	FetchCmd.AddCommand(fetchAmazonCmd)
	FetchCmd.AddCommand(fetchSUSECmd)
	FetchCmd.AddCommand(fetchDebianCmd)
	FetchCmd.AddCommand(fetchUbuntuCmd)
	FetchCmd.AddCommand(fetchAlpineCmd)

	// flags
	FetchCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	FetchCmd.PersistentFlags().String("dbpath", filepath.Join(os.Getenv("PWD"), "oval.sqlite3"), "/path/to/sqlite3 or SQL connection string")
	FetchCmd.PersistentFlags().String("dbtype", "sqlite3", "Database type to store data in (sqlite3, mysql, postgres or redis supported)")
	FetchCmd.PersistentFlags().Int("batch-size", 25, "The number of batch size to insert.")
	FetchCmd.PersistentFlags().String("http-proxy", "", "http://proxy-url:port")
	FetchCmd.PersistentFlags().Bool("no-details", false, "without vulnerability details")
}
