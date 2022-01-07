package convert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/fetcher"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

var convertAlpineCmd = &cobra.Command{
	Use:   "alpine",
	Short: "Convert Vulnerability dictionary from Alpine secdb",
	Long:  `Convert Vulnerability dictionary from Alpine secdb`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("vuln-dir", cmd.Parent().PersistentFlags().Lookup("vuln-dir")); err != nil {
			return err
		}

		if err := viper.BindPFlag("http-proxy", cmd.Parent().PersistentFlags().Lookup("http-proxy")); err != nil {
			return err
		}

		return nil
	},
	RunE: convertAlpine,
}

var supportAlpineVers = []string{"3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"}

func convertAlpine(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	vulnDir := filepath.Join(viper.GetString("vuln-dir"), "alpine")
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

	log15.Info("Fetching Alpine CVEs")
	results, err := fetcher.FetchAlpineFiles(supportAlpineVers)
	if err != nil {
		return xerrors.Errorf("Failed to fetch files. err: %w", err)
	}

	// Join community.yaml, main.yaml
	type T struct {
		url  string
		defs []models.Definition
	}
	m := map[string]T{}
	for _, r := range results {
		secdb, err := unmarshalYml(r.Body)
		if err != nil {
			return xerrors.Errorf("Failed to unmarshal yml. err: %w", err)
		}

		defs := models.ConvertAlpineToModel(secdb)
		if t, ok := m[r.Target]; ok {
			t.defs = append(t.defs, defs...)
			m[r.Target] = t
		} else {
			ss := strings.Split(r.URL, "/")
			m[r.Target] = T{
				url:  strings.Join(ss[len(ss)-3:len(ss)-1], "/"),
				defs: defs,
			}
		}
	}

	log15.Info("Converting Alpine CVEs")
	verDefsMap := map[string]map[string][]models.Definition{}
	for target, t := range m {
		verDefsMap[target] = map[string][]models.Definition{}
		for _, def := range t.defs {
			for _, cve := range def.Advisory.Cves {
				verDefsMap[target][cve.CveID] = append(verDefsMap[target][cve.CveID], models.Definition{
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
	}

	log15.Info("Deleting Old Alpine CVEs")
	dirs, err := filepath.Glob(filepath.Join(vulnDir, "*"))
	if err != nil {
		return xerrors.Errorf("Failed to get all dirs in vuln directory. err: %w", err)
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return xerrors.Errorf("Failed to remove vuln data file. err: %w", err)
		}
	}

	log15.Info("Creating Alpine CVEs")
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
	if err := setLastUpdatedDate("goval-dictionary/alpine"); err != nil {
		return xerrors.Errorf("Failed to set last updated date. err: %w", err)
	}

	return nil
}

func unmarshalYml(data []byte) (*models.AlpineSecDB, error) {
	t := models.AlpineSecDB{}
	err := yaml.Unmarshal([]byte(data), &t)
	if err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal: %w", err)
	}
	return &t, nil
}
