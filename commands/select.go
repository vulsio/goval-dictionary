package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/k0kubun/pp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/db"
	"github.com/vulsio/goval-dictionary/models"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
)

// SelectCmd is Subcommand for fetch RedHat OVAL
var selectCmd = &cobra.Command{
	Use:   "select",
	Short: "Select from DB",
	Long:  `Select from DB`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("debug-sql", cmd.PersistentFlags().Lookup("debug-sql")); err != nil {
			return err
		}

		if err := viper.BindPFlag("dbpath", cmd.PersistentFlags().Lookup("dbpath")); err != nil {
			return err
		}

		if err := viper.BindPFlag("dbtype", cmd.PersistentFlags().Lookup("dbtype")); err != nil {
			return err
		}

		if err := viper.BindPFlag("by-package", cmd.PersistentFlags().Lookup("by-package")); err != nil {
			return err
		}

		if err := viper.BindPFlag("by-cveid", cmd.PersistentFlags().Lookup("by-cveid")); err != nil {
			return err
		}

		return nil
	},
	RunE: executeSelect,
}

func init() {
	selectCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	selectCmd.PersistentFlags().String("dbpath", filepath.Join(os.Getenv("PWD"), "oval.sqlite3"), "/path/to/sqlite3 or SQL connection string")
	selectCmd.PersistentFlags().String("dbtype", "sqlite3", "Database type to store data in (sqlite3, mysql, postgres or redis supported)")
	selectCmd.PersistentFlags().Bool("by-package", false, "select OVAL by package name")
	selectCmd.PersistentFlags().Bool("by-cveid", false, "select OVAL by CVE-ID")
}

func executeSelect(_ *cobra.Command, args []string) error {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	flagPkg := viper.GetBool("by-package")
	flagCveID := viper.GetBool("by-cveid")

	if (!flagPkg && !flagCveID) || (flagPkg && flagCveID) {
		return xerrors.New("Failed to select command. err: specify --by-package or --by-cveid")
	}

	if len(args) < 3 {
		if flagPkg {
			return xerrors.Errorf(`
			Usage:
			select OVAL by package name
			$ goval-dictionary select --by-package [osFamily] [osVersion] [Package Name] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
		if flagCveID {
			return xerrors.Errorf(`
			Usage:
			select OVAL by CVE-ID
			$ goval-dictionary select --by-cveid [osFamily] [osVersion] [CVE-ID] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
	} else if len(args) > 4 {
		if flagPkg {
			return xerrors.Errorf(`
			Usage:
			select OVAL by package name
			$ goval-dictionary select --by-package [osFamily] [osVersion] [Package Name] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
		if flagCveID {
			return xerrors.Errorf(`
			Usage:
			select OVAL by CVE-ID
			$ goval-dictionary select --by-cveid [osFamily] [osVersion] [CVE-ID] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
	}

	family := args[0]
	release := args[1]
	arg := args[2]
	arch := ""
	if len(args) == 4 {
		switch family {
		case config.Amazon, config.Oracle:
			arch = args[3]
		default:
			return xerrors.Errorf("Family: %s cannot use the Architecture argument.", family)
		}
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to open DB. Close DB connection before select. err: %w", err)
		}
		return err
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to select command. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	if flagPkg {
		dfs, err := driver.GetByPackName(family, release, arg, arch)
		if err != nil {
			return xerrors.Errorf("Failed to get cve by package. err: %w", err)
		}

		for _, d := range dfs {
			for _, cve := range d.Advisory.Cves {
				fmt.Printf("%s\n", cve.CveID)
				for _, pack := range d.AffectedPacks {
					fmt.Printf("    %v\n", pack)
				}
			}
		}
		fmt.Println("------------------")
		pp.ColoringEnabled = false
		_, _ = pp.Println(dfs)
	}

	if flagCveID {
		dfs, err := driver.GetByCveID(family, release, arg, arch)
		if err != nil {
			return xerrors.Errorf("Failed to get cve by cveID. err: %w", err)
		}
		for _, d := range dfs {
			fmt.Printf("%s\n", d.Title)
			fmt.Printf("%v\n", d.Advisory.Cves)
		}
		fmt.Println("------------------")
		pp.ColoringEnabled = false
		_, _ = pp.Println(dfs)
	}

	return nil
}
