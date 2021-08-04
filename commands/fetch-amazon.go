package commands

import (
	"fmt"
	"time"

	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// fetchAmazonCmd is Subcommand for fetch Amazon ALAS RSS
// https://alas.aws.amazon.com/alas.rss
var fetchAmazonCmd = &cobra.Command{
	Use:   "amazon",
	Short: "Fetch Vulnerability dictionary from Amazon ALAS",
	Long:  `Fetch Vulnerability dictionary from Amazon ALAS`,
	RunE:  fetchAmazon,
}

func init() {
	fetchCmd.AddCommand(fetchAmazonCmd)
}

func fetchAmazon(cmd *cobra.Command, args []string) (err error) {
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	uinfo, err := fetcher.FetchUpdateInfoAmazonLinux1()
	if err != nil {
		log15.Error("Failed to fetch updateinfo for Amazon Linux1", "err", err)
		return err
	}
	root := models.Root{
		Family:      c.Amazon,
		OSVersion:   "1",
		Definitions: models.ConvertAmazonToModel(uinfo),
		Timestamp:   time.Now(),
	}
	log15.Info(fmt.Sprintf("%d CVEs for Amazon Linux1. Inserting to DB", len(root.Definitions)))
	if err := execute(&root); err != nil {
		log15.Error("Failed to Insert Amazon1", "err", err)
		return err
	}

	uinfo, err = fetcher.FetchUpdateInfoAmazonLinux2()
	if err != nil {
		log15.Error("Failed to fetch updateinfo for Amazon Linux2", "err", err)
		return err
	}
	root = models.Root{
		Family:      c.Amazon,
		OSVersion:   "2",
		Definitions: models.ConvertAmazonToModel(uinfo),
		Timestamp:   time.Now(),
	}
	log15.Info(fmt.Sprintf("%d CVEs for Amazon Linux2. Inserting to DB", len(root.Definitions)))
	if err := execute(&root); err != nil {
		log15.Error("Failed to Insert Amazon2", "err", err)
		return err
	}
	return nil
}

func execute(root *models.Root) error {
	driver, locked, err := db.NewDB(c.Amazon, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			return fmt.Errorf("Failed to open DB. Close DB connection before fetching: %w", err)
		}
		return fmt.Errorf("Failed to open DB: %w", err)
	}
	defer func() {
		err := driver.CloseDB()
		if err != nil {
			log15.Error("Failed to close DB", "err", err)
		}
	}()

	fmeta := models.FetchMeta{
		Timestamp: time.Now(),
		FileName:  fmt.Sprintf("FetchUpdateInfoAmazonLinux%s", root.OSVersion),
	}

	if err := driver.InsertOval(c.Amazon, root, fmeta); err != nil {
		return fmt.Errorf("Failed to insert OVAL: %w", err)
	}
	if err := driver.InsertFetchMeta(fmeta); err != nil {
		log15.Error("Failed to insert meta", "err", err)
		return fmt.Errorf("Failed to insert FetchMeta: %w", err)
	}
	log15.Info("Finish", "Updated", len(root.Definitions))
	return nil
}
