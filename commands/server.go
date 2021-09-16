package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	server "github.com/vulsio/goval-dictionary/server"
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
	logDir := viper.GetString("log-dir")
	log15.Info("Starting HTTP Server...")
	if err = server.Start(logDir); err != nil {
		log15.Error("Failed to start server.", "err", err)
		return err
	}

	return nil
}
