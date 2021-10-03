package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/db"
	"github.com/vulsio/goval-dictionary/models"
	server "github.com/vulsio/goval-dictionary/server"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
)

// ServerCmd is Subcommand for OVAL dictionary HTTP Server
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start OVAL dictionary HTTP server",
	Long:  `Start OVAL dictionary HTTP server`,
	RunE:  executeServer,
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.PersistentFlags().String("bind", "127.0.0.1", "HTTP server bind to IP address")
	_ = viper.BindPFlag("bind", serverCmd.PersistentFlags().Lookup("bind"))

	serverCmd.PersistentFlags().String("port", "1324", "HTTP server port number")
	_ = viper.BindPFlag("port", serverCmd.PersistentFlags().Lookup("port"))
}

func executeServer(cmd *cobra.Command, args []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to initialize DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to start server. SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	log15.Info("Starting HTTP Server...")
	if err = server.Start(viper.GetBool("log-to-file"), viper.GetString("log-dir"), driver); err != nil {
		return xerrors.Errorf("Failed to start server. err: %w", err)
	}

	return nil
}
