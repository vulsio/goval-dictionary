package util

import (
	"time"

	"github.com/inconshreveable/log15"
)

// ParsedOrDefaultTime returns time.Parse(layout, value), or time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC) if it failed to parse
func ParsedOrDefaultTime(layout, value string) time.Time {
	defaultTime := time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
	if value == "" {
		return defaultTime
	}
	t, err := time.Parse(layout, value)
	if err != nil {
		log15.Warn("Failed to parse string", "timeformat", layout, "target string", value, "err", err)
		return defaultTime
	}
	return t
}
