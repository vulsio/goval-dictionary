package config

import (
	valid "github.com/asaskevich/govalidator"
	log "github.com/kotakanbe/goval-dictionary/log"
)

// Conf has Configuration
var Conf Config

// Config has config
type Config struct {
	Debug     bool
	DebugSQL  bool
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
			log.Errorf("SQLite3 DB path must be a *Absolute* file path. dbpath: %s", p.DBPath)
			return false
		}
	}

	_, err := valid.ValidateStruct(p)
	if err != nil {
		log.Errorf("error: " + err.Error())
		return false
	}
	return true
}
