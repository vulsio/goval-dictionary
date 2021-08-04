package commands

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/k0kubun/pp"
	"github.com/kotakanbe/goval-dictionary/db"
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

	if flagPkg && len(args) != 4 {
		log15.Error(`
		Usage:
		select OVAL by package name
		./goval-dictionary select --by-package redhat 7 java-1.7.0-openjdk x86_64
		`)
		return xerrors.New("Failed to set by-package option args.")
	}

	if flagCveID && len(args) != 4 {
		log15.Error(`
		Usage:
		select OVAL by CVE-ID
		./goval-dictionary select --by-cveid redhat 7 CVE-2015-1111 x86)64
		`)
		return xerrors.New("Failed to set by-cveid option args.")
	}

	driver, locked, err := db.NewDB(args[0], viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before select", "err", err)
			return err
		}
		log15.Error("Failed to open DB", "err", err)
		return err
	}

	if flagPkg {
		dfs, err := driver.GetByPackName(args[0], args[1], args[2], args[3])
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
		dfs, err := driver.GetByCveID(args[0], args[1], args[2], args[3])
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
