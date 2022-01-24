package util

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"
)

// CveIDPattern is regexp matches to `CVE-\d{4}-\d{4,}`
var CveIDPattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

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
	defaultLogDir := "/var/log/goval-dictionary"
	if runtime.GOOS == "windows" {
		defaultLogDir = filepath.Join(os.Getenv("APPDATA"), "goval-dictionary")
	}
	return defaultLogDir
}

// SetLogger set logger
func SetLogger(logToFile bool, logDir string, debug, logJSON bool) error {
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

	var handler log15.Handler
	if logToFile {
		if _, err := os.Stat(logDir); err != nil {
			if os.IsNotExist(err) {
				if err := os.Mkdir(logDir, 0700); err != nil {
					return xerrors.Errorf("Failed to create log directory. err: %w", err)
				}
			} else {
				return xerrors.Errorf("Failed to check log directory. err: %w", err)
			}
		}

		logPath := filepath.Join(logDir, "goval-dictionary.log")
		if _, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
			return xerrors.Errorf("Failed to open a log file. err: %w", err)
		}
		handler = log15.MultiHandler(
			log15.Must.FileHandler(logPath, logFormat),
			lvlHandler,
		)
	} else {
		handler = lvlHandler
	}
	log15.Root().SetHandler(handler)
	return nil
}

// UniqueStrings eliminates duplication from []string
func UniqueStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	uniq := make([]string, 0, len(m))
	for v := range m {
		uniq = append(uniq, v)
	}
	return uniq
}
