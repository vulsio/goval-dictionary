package commands

import (
	"fmt"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	c "github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/db"
	"github.com/vulsio/goval-dictionary/fetcher"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
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
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
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

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		log15.Error("Failed to get FetchMeta from DB.", "err", err)
		return err
	}
	if fetchMeta.OutDated() {
		log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
		return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
	}

	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		log15.Error("Failed to upsert FetchMeta to DB.", "err", err)
		return err
	}

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
	if err := execute(driver, &root); err != nil {
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
	if err := execute(driver, &root); err != nil {
		log15.Error("Failed to Insert Amazon2", "err", err)
		return err
	}

	return nil
}

func execute(driver db.DB, root *models.Root) error {
	timestamp, err := time.Parse("2006-01-02T15:04:05Z", time.Now().Format("2006-01-02T15:04:05Z"))
	if err != nil {
		return fmt.Errorf("Failed to parse timestamp. err: %w", err)
	}

	fmeta := models.FileMeta{
		Timestamp: timestamp,
		FileName:  fmt.Sprintf("FetchUpdateInfoAmazonLinux%s", root.OSVersion),
	}

	if err := driver.InsertOval(root, fmeta); err != nil {
		return fmt.Errorf("Failed to insert OVAL: %w", err)
	}
	if err := driver.InsertFileMeta(fmeta); err != nil {
		log15.Error("Failed to insert meta", "err", err)
		return fmt.Errorf("Failed to insert FileMeta: %w", err)
	}
	log15.Info("Finish", "Updated", len(root.Definitions))

	return nil
}
