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
	"github.com/labstack/echo/engine/standard"
	"github.com/labstack/echo/middleware"
)

// Start starts CVE dictionary HTTP Server.
func Start(logDir string, driver db.DB) error {
	e := echo.New()
	e.SetDebug(config.Conf.Debug)

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
	e.Get("/health", health())
	e.Get("/cves/:family/:release/:id", getByCveID(driver))
	e.Get("/packs/:family/:release/:pack", getByPackName(driver))
	e.Get("/count/:family/:release", countOvalDefs(driver))
	e.Get("/lastmodified/:family/:release", getLastModified(driver))
	//  e.Post("/cpes", getByPackName())

	bindURL := fmt.Sprintf("%s:%s", config.Conf.Bind, config.Conf.Port)
	log15.Info("Listening...", "URL", bindURL)

	e.Run(standard.New(bindURL))
	return nil
}

// Handler
func health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	}
}

// Handler
func getByCveID(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		cveID := c.Param("id")
		log15.Debug("Params", "Family", family, "Release", release, "CveID", cveID)
		driver.NewOvalDB(family)
		defs, err := driver.GetByCveID(release, cveID)
		if err != nil {
			log15.Error("Failed to get by CveID.", "err", err)
		}
		return c.JSON(http.StatusOK, defs)
	}
}

func getByPackName(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		pack := c.Param("pack")
		log15.Debug("Params", "Family", family, "Release", release, "Pack", pack)
		driver.NewOvalDB(family)
		defs, err := driver.GetByPackName(release, pack)
		if err != nil {
			log15.Error("Failed to get by CveID.", "err", err)
		}
		return c.JSON(http.StatusOK, defs)
	}
}

func countOvalDefs(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		log15.Debug("Params", "Family", family, "Release", release)
		driver.NewOvalDB(family)
		count, err := driver.CountDefs(family, release)
		log15.Debug("Count", "Count", count)
		if err != nil {
			log15.Error("Failed to count OVAL defs.", "err", err)
		}
		return c.JSON(http.StatusOK, count)
	}
}

func getLastModified(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		log15.Debug("getLastModified", "Family", family, "Release", release)
		driver.NewOvalDB(family)
		t := driver.GetLastModified(family, release)
		return c.JSON(http.StatusOK, t)
	}
}
