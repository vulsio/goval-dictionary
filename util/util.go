package util

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/inconshreveable/log15"
	"github.com/k0kubun/pp"
)

// GenWorkers generate workers
func GenWorkers(num int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			for f := range tasks {
				f()
			}
		}()
	}
	return tasks
}

// GetDefaultLogDir returns default log directory
func GetDefaultLogDir() string {
	defaultLogDir := "/var/log/vuls"
	if runtime.GOOS == "windows" {
		defaultLogDir = filepath.Join(os.Getenv("APPDATA"), "vuls")
	}
	return defaultLogDir
}

// SetLogger set logger
func SetLogger(logDir string, quiet, debug, logJSON bool) {
	stderrHandler := log15.StderrHandler
	logFormat := log15.LogfmtFormat()
	if logJSON {
		logFormat = log15.JsonFormatEx(false, true)
		stderrHandler = log15.StreamHandler(os.Stderr, logFormat)
	}

	lvlHandler := log15.LvlFilterHandler(log15.LvlInfo, stderrHandler)
	if debug {
		lvlHandler = log15.LvlFilterHandler(log15.LvlDebug, stderrHandler)
	}
	if quiet {
		lvlHandler = log15.LvlFilterHandler(log15.LvlDebug, log15.DiscardHandler())
		pp.SetDefaultOutput(ioutil.Discard)
	}

	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.Mkdir(logDir, 0700); err != nil {
			log15.Error("Failed to create log directory", "err", err)
		}
	}
	var handler log15.Handler
	if _, err := os.Stat(logDir); err == nil {
		logPath := filepath.Join(logDir, "goval-dictionary.log")
		if _, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
			log15.Error("Failed to create a log file", "err", err)
			handler = lvlHandler
		} else {
			handler = log15.MultiHandler(
				log15.Must.FileHandler(logPath, logFormat),
				lvlHandler,
			)
		}
	} else {
		handler = lvlHandler
	}
	log15.Root().SetHandler(handler)
}
