package config

import (
	valid "github.com/asaskevich/govalidator"
	"github.com/inconshreveable/log15"
)

const (
	// RedHat is
	RedHat = "redhat"

	// CentOS is
	CentOS = "centos"

	// Debian is
	Debian = "debian"

	// Ubuntu is
	Ubuntu = "ubuntu"

	// Ubuntu12 is Ubuntu Precise
	Ubuntu12 = "precise"

	// Ubuntu14 is Ubuntu Trusty
	Ubuntu14 = "trusty"

	// Ubuntu16 is Ubuntu Xenial
	Ubuntu16 = "xenial"

	// Ubuntu17 is Ubuntu Artful
	Ubuntu17 = "artful"

	// Ubuntu18 is Ubuntu Bionic
	Ubuntu18 = "bionic"

	// Ubuntu19 is Disco Dingo
	Ubuntu19 = "disco"

	// Debian7 is wheezy
	Debian7 = "wheezy"

	// Debian8 is jessie
	Debian8 = "jessie"

	// Debian9 is stretch
	Debian9 = "stretch"

	// Debian10 is buster
	Debian10 = "buster"

	// OpenSUSE is
	OpenSUSE = "opensuse"

	// OpenSUSELeap is
	OpenSUSELeap = "opensuse.leap"

	// SUSEEnterpriseServer is
	SUSEEnterpriseServer = "suse.linux.enterprise.server"

	// SUSEEnterpriseDesktop is
	SUSEEnterpriseDesktop = "suse.linux.enterprise.desktop"

	// SUSEOpenstackCloud is
	SUSEOpenstackCloud = "suse.openstack.cloud"

	// Oracle is
	Oracle = "oracle"

	// Alpine is
	Alpine = "alpine"

	// Amazon is
	Amazon = "amazon"
)

// Conf has Configuration
var Conf Config

// Config has config
type Config struct {
	Debug     bool
	DebugSQL  bool
	Quiet     bool
	NoDetails bool
	DBPath    string
	DBType    string
	Bind      string `valid:"ipv4"`
	Port      string `valid:"port"`
	HTTPProxy string
}

// Validate validates configuration
func (p *Config) Validate() bool {
	if p.DBType == "sqlite3" {
		if ok, _ := valid.IsFilePath(p.DBPath); !ok {
			log15.Error("SQLite3 DB path must be a *Absolute* file path.", "dbpath", p.DBPath)
			return false
		}
	}

	_, err := valid.ValidateStruct(p)
	if err != nil {
		log15.Error("Invalid Struct", "err", err)
		return false
	}
	return true
}
