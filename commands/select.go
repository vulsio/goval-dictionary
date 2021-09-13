package commands

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

// SelectCmd is Subcommand for fetch RedHat OVAL
var selectCmd = &cobra.Command{
	Use:   "select",
	Short: "Select from DB",
	Long:  `Select from DB`,
	RunE:  executeSelect,
}

func init() {
	RootCmd.AddCommand(selectCmd)

	selectCmd.PersistentFlags().Bool("by-package", false, "select OVAL by package name")
	_ = viper.BindPFlag("by-package", selectCmd.PersistentFlags().Lookup("by-package"))

	selectCmd.PersistentFlags().Bool("by-cveid", false, "select OVAL by CVE-ID")
	_ = viper.BindPFlag("by-cveid", selectCmd.PersistentFlags().Lookup("by-cveid"))
}

func executeSelect(cmd *cobra.Command, args []string) error {
	util.SetLogger(viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json"))

	flagPkg := viper.GetBool("by-package")
	flagCveID := viper.GetBool("by-cveid")

	if (!flagPkg && !flagCveID) || (flagPkg && flagCveID) {
		log15.Error("Specify --by-package or --by-cveid")
		return xerrors.New("Failed to select command. err: specify --by-package or --by-cveid")
	}

	if len(args) < 3 {
		if flagPkg {
			log15.Error(`
			Usage:
			select OVAL by package name
			$ goval-dictionary select --by-package [osFamily] [osVersion] [Package Name] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
		if flagCveID {
			log15.Error(`
			Usage:
			select OVAL by CVE-ID
			$ goval-dictionary select --by-cveid [osFamily] [osVersion] [CVE-ID] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
		return xerrors.New("too few arguments.")
	} else if len(args) > 4 {
		if flagPkg {
			log15.Error(`
			Usage:
			select OVAL by package name
			$ goval-dictionary select --by-package [osFamily] [osVersion] [Package Name] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
		if flagCveID {
			log15.Error(`
			Usage:
			select OVAL by CVE-ID
			$ goval-dictionary select --by-cveid [osFamily] [osVersion] [CVE-ID] [Optional: Architecture (Oracle, Amazon Only)]
			`)
		}
		return xerrors.New("too many arguments.")
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
			log15.Error(fmt.Sprintf("Family: %s cannot use the Architecture argument.", family))
		}
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before select", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		log15.Error("Failed to get FetchMeta from DB.", "err", err)
		return err
	}
	if fetchMeta.OutDated() {
		log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
		return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
	}

	if flagPkg {
		dfs, err := driver.GetByPackName(family, release, arg, arch)
		if err != nil {
			//TODO Logger
			log15.Error("Failed to get cve by package.", "err", err)
			return err
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
			log15.Crit("Failed to get cve by cveID", "err", err)
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
