package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

// Start starts CVE dictionary HTTP Server.
func Start(logDir string) error {
	e := echo.New()
	e.Debug = config.Conf.Debug

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// setup access logger
	logPath := filepath.Join(logDir, "access.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		if _, err := os.Create(logPath); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Output: f,
	}))

	// Routes
	e.GET("/health", health())
	e.GET("/packs/:family/:release/:pack/:arch", getByPackName())
	e.GET("/packs/:family/:release/:pack", getByPackName())
	e.GET("/count/:family/:release", countOvalDefs())
	e.GET("/lastmodified/:family/:release", getLastModified())
	//  e.Post("/cpes", getByPackName())

	bindURL := fmt.Sprintf("%s:%s", config.Conf.Bind, config.Conf.Port)
	log15.Info("Listening...", "URL", bindURL)
	return e.Start(bindURL)
}

// Handler
func health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	}
}

func getByPackName() echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		pack := c.Param("pack")
		arch := c.Param("arch")
		log15.Debug("Params", "Family", family, "Release", release, "Pack", pack, "arch", arch)

		driver, locked, err := db.NewDB(family, config.Conf.DBType, config.Conf.DBPath, config.Conf.DebugSQL)
		if err != nil {
			msg := fmt.Sprintf("Failed to Open DB: %s", err)
			if locked {
				msg += " Close DB connection"
			}
			log15.Error(msg)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		defer driver.CloseDB()
		defs, err := driver.GetByPackName(family, release, pack, arch)
		if err != nil {
			log15.Error("Failed to get by CveID.", "err", err)
		}
		return c.JSON(http.StatusOK, defs)
	}
}

func countOvalDefs() echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		log15.Debug("Params", "Family", family, "Release", release)
		driver, locked, err := db.NewDB(family, config.Conf.DBType, config.Conf.DBPath, config.Conf.DebugSQL)
		if err != nil {
			msg := fmt.Sprintf("Failed to Open DB: %s", err)
			if locked {
				msg += " Close DB connection"
			}
			log15.Error(msg)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		defer driver.CloseDB()
		count, err := driver.CountDefs(family, release)
		log15.Debug("Count", "Count", count)
		if err != nil {
			log15.Error("Failed to count OVAL defs.", "err", err)
		}
		return c.JSON(http.StatusOK, count)
	}
}

func getLastModified() echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		log15.Debug("getLastModified", "Family", family, "Release", release)
		driver, locked, err := db.NewDB(family, config.Conf.DBType, config.Conf.DBPath, config.Conf.DebugSQL)
		if err != nil {
			msg := fmt.Sprintf("Failed to Open DB: %s", err)
			if locked {
				msg += " Close DB connection"
			}
			log15.Error(msg)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		defer driver.CloseDB()
		t := driver.GetLastModified(family, release)
		return c.JSON(http.StatusOK, t)
	}
}
