package server

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
	"github.com/vulsio/goval-dictionary/db"
	"github.com/vulsio/goval-dictionary/models"
	"golang.org/x/xerrors"
)

// Start starts CVE dictionary HTTP Server.
func Start(logDir string) error {
	e := echo.New()
	e.Debug = viper.GetBool("debug")

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// setup access logger
	logPath := filepath.Join(logDir, "access.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		if _, err := os.Create(logPath); err != nil {
			log15.Error("Failed to create log dir", logPath, err)
		}
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log15.Error("Failed to open log file", logPath, err)
	}
	defer f.Close()
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Output: f,
	}))

	// Routes
	e.GET("/health", health())
	e.GET("/packs/:family/:release/:pack/:arch", getByPackName())
	e.GET("/packs/:family/:release/:pack", getByPackName())
	e.GET("/cves/:family/:release/:id/:arch", getByCveID())
	e.GET("/cves/:family/:release/:id", getByCveID())
	e.GET("/count/:family/:release", countOvalDefs())
	e.GET("/lastmodified/:family/:release", getLastModified())
	//  e.Post("/cpes", getByPackName())

	bindURL := fmt.Sprintf("%s:%s", viper.GetString("bind"), viper.GetString("port"))
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
		decodePack, err := url.QueryUnescape(pack)
		if err != nil {
			log15.Error(fmt.Sprintf("Failed to Decode Package Name: %s", err))
			return c.JSON(http.StatusBadRequest, nil)
		}

		log15.Debug("Params", "Family", family, "Release", release, "Pack", pack, "DecodePack", decodePack, "arch", arch)

		driver, locked, err := db.NewDB(family, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
		if err != nil {
			msg := fmt.Sprintf("Failed to Open DB: %s", err)
			if locked {
				msg += " Close DB connection"
			}
			log15.Error(msg)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		defer func() {
			_ = driver.CloseDB()
		}()

		fetchMeta, err := driver.GetFetchMeta()
		if err != nil {
			log15.Error("Failed to get FetchMeta from DB.", "err", err)
			return err
		}
		if fetchMeta.OutDated() {
			log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
			return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
		}

		defs, err := driver.GetByPackName(family, release, decodePack, arch)
		if err != nil {
			log15.Error("Failed to get by Package Name.", "err", err)
		}
		return c.JSON(http.StatusOK, defs)
	}
}

func getByCveID() echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		family := strings.ToLower(c.Param("family"))
		release := c.Param("release")
		cveID := c.Param("id")
		arch := c.Param("arch")
		log15.Debug("Params", "Family", family, "Release", release, "CveID", cveID, "arch", arch)

		driver, locked, err := db.NewDB(family, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
		if err != nil {
			msg := fmt.Sprintf("Failed to Open DB: %s", err)
			if locked {
				msg += " Close DB connection"
			}
			log15.Error(msg)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		defer func() {
			_ = driver.CloseDB()
		}()

		fetchMeta, err := driver.GetFetchMeta()
		if err != nil {
			log15.Error("Failed to get FetchMeta from DB.", "err", err)
			return err
		}
		if fetchMeta.OutDated() {
			log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
			return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
		}

		defs, err := driver.GetByCveID(family, release, cveID, arch)
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
		driver, locked, err := db.NewDB(family, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
		if err != nil {
			msg := fmt.Sprintf("Failed to Open DB: %s", err)
			if locked {
				msg += " Close DB connection"
			}
			log15.Error(msg)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		defer func() {
			_ = driver.CloseDB()
		}()

		fetchMeta, err := driver.GetFetchMeta()
		if err != nil {
			log15.Error("Failed to get FetchMeta from DB.", "err", err)
			return err
		}
		if fetchMeta.OutDated() {
			log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
			return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
		}

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
		driver, locked, err := db.NewDB(family, viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
		if err != nil {
			msg := fmt.Sprintf("Failed to Open DB: %s", err)
			if locked {
				msg += " Close DB connection"
			}
			log15.Error(msg)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		defer func() {
			_ = driver.CloseDB()
		}()

		fetchMeta, err := driver.GetFetchMeta()
		if err != nil {
			log15.Error("Failed to get FetchMeta from DB.", "err", err)
			return err
		}
		if fetchMeta.OutDated() {
			log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
			return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
		}

		t, err := driver.GetLastModified(family, release)
		if err != nil {
			log15.Error(fmt.Sprintf("Failed to GetLastModified: %s", err))
			return c.JSON(http.StatusInternalServerError, nil)
		}

		return c.JSON(http.StatusOK, t)
	}
}
