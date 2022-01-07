package convert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/fetcher"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
)

var convertAmazonCmd = &cobra.Command{
	Use:   "amazon",
	Short: "Convert Vulnerability dictionary from Amazon ALAS",
	Long:  `Convert Vulnerability dictionary from Amazon ALAS`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("vuln-dir", cmd.Parent().PersistentFlags().Lookup("vuln-dir")); err != nil {
			return err
		}

		if err := viper.BindPFlag("http-proxy", cmd.Parent().PersistentFlags().Lookup("http-proxy")); err != nil {
			return err
		}

		return nil
	},
	RunE: convertAmazon,
}

func convertAmazon(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	vulnDir := filepath.Join(viper.GetString("vuln-dir"), "amazon")
	if f, err := os.Stat(vulnDir); err != nil {
		if !os.IsNotExist(err) {
			return xerrors.Errorf("Failed to check vuln directory. err: %w", err)
		}
		if err := os.MkdirAll(vulnDir, 0700); err != nil {
			return xerrors.Errorf("Failed to create vuln directory. err: %w", err)
		}
	} else if !f.IsDir() {
		return xerrors.Errorf("Failed to check vuln directory. err: %s is not directory", vulnDir)
	}

	verDefsMap := map[string]map[string][]models.Definition{}

	log15.Info("Fetching Amazon Linux1 CVEs")
	uinfo, err := fetcher.FetchUpdateInfoAmazonLinux1()
	if err != nil {
		return xerrors.Errorf("Failed to fetch updateinfo for Amazon Linux1. err: %w", err)
	}
	log15.Info("Converting Amazon Linux1 CVEs")
	verDefsMap["1"] = map[string][]models.Definition{}
	for _, def := range models.ConvertAmazonToModel(uinfo) {
		for _, cve := range def.Advisory.Cves {
			verDefsMap["1"][cve.CveID] = append(verDefsMap["1"][cve.CveID], models.Definition{
				DefinitionID: def.DefinitionID,
				Title:        def.Title,
				Description:  def.Description,
				Advisory: models.Advisory{
					Severity:        def.Advisory.Severity,
					Cves:            []models.Cve{cve},
					Bugzillas:       def.Advisory.Bugzillas,
					AffectedCPEList: def.Advisory.AffectedCPEList,
					Issued:          def.Advisory.Issued,
					Updated:         def.Advisory.Updated,
				},
				Debian:        def.Debian,
				AffectedPacks: def.AffectedPacks,
				References:    def.References,
			})
		}
	}

	log15.Info("Fetching Amazon Linux2 CVEs")
	uinfo, err = fetcher.FetchUpdateInfoAmazonLinux2()
	if err != nil {
		return xerrors.Errorf("Failed to fetch updateinfo for Amazon Linux2. err: %w", err)
	}
	log15.Info("Converting Amazon Linux2 CVEs")
	verDefsMap["2"] = map[string][]models.Definition{}
	for _, def := range models.ConvertAmazonToModel(uinfo) {
		for _, cve := range def.Advisory.Cves {
			verDefsMap["2"][cve.CveID] = append(verDefsMap["2"][cve.CveID], models.Definition{
				DefinitionID: def.DefinitionID,
				Title:        def.Title,
				Description:  def.Description,
				Advisory: models.Advisory{
					Severity:        def.Advisory.Severity,
					Cves:            []models.Cve{cve},
					Bugzillas:       def.Advisory.Bugzillas,
					AffectedCPEList: def.Advisory.AffectedCPEList,
					Issued:          def.Advisory.Issued,
					Updated:         def.Advisory.Updated,
				},
				Debian:        def.Debian,
				AffectedPacks: def.AffectedPacks,
				References:    def.References,
			})
		}
	}

	log15.Info("Fetching Amazon Linux2022 CVEs")
	uinfo, err = fetcher.FetchUpdateInfoAmazonLinux2022()
	if err != nil {
		return xerrors.Errorf("Failed to fetch updateinfo for Amazon Linux2022. err: %w", err)
	}
	log15.Info("Converting Amazon Linux2022 CVEs")
	verDefsMap["2022"] = map[string][]models.Definition{}
	for _, def := range models.ConvertAmazonToModel(uinfo) {
		for _, cve := range def.Advisory.Cves {
			verDefsMap["2022"][cve.CveID] = append(verDefsMap["2022"][cve.CveID], models.Definition{
				DefinitionID: def.DefinitionID,
				Title:        def.Title,
				Description:  def.Description,
				Advisory: models.Advisory{
					Severity:        def.Advisory.Severity,
					Cves:            []models.Cve{cve},
					Bugzillas:       def.Advisory.Bugzillas,
					AffectedCPEList: def.Advisory.AffectedCPEList,
					Issued:          def.Advisory.Issued,
					Updated:         def.Advisory.Updated,
				},
				Debian:        def.Debian,
				AffectedPacks: def.AffectedPacks,
				References:    def.References,
			})
		}
	}

	log15.Info("Deleting Old Amazon CVEs")
	dirs, err := filepath.Glob(filepath.Join(vulnDir, "*"))
	if err != nil {
		return xerrors.Errorf("Failed to get all dirs in vuln directory. err: %w", err)
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return xerrors.Errorf("Failed to remove vuln data file. err: %w", err)
		}
	}

	log15.Info("Creating Amazon CVEs")
	for ver, defs := range verDefsMap {
		if err := os.MkdirAll(filepath.Join(vulnDir, ver), 0700); err != nil {
			return xerrors.Errorf("Failed to create vuln directory. err: %w", err)
		}

		for cveID, def := range defs {
			f, err := os.Create(filepath.Join(vulnDir, ver, fmt.Sprintf("%s.json", cveID)))
			if err != nil {
				return xerrors.Errorf("Failed to create vuln data file. err: %w", err)
			}

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(def); err != nil {
				_ = f.Close() // ignore error; Write error takes precedence
				return xerrors.Errorf("Failed to encode vuln data. err: %w", err)
			}

			if err := f.Close(); err != nil {
				return xerrors.Errorf("Failed to close vuln data file. err: %w", err)
			}
		}
	}

	log15.Info("Setting Last Updated Date")
	if err := setLastUpdatedDate("goval-dictionary/amazon"); err != nil {
		return xerrors.Errorf("Failed to set last updated date. err: %w", err)
	}

	return nil
}
