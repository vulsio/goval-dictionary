package util

import (
	"testing"
	"time"
)

func TestParsedOrDefaultTime(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		layout string
		want   time.Time
	}{
		{
			name:   "success to parse",
			in:     "2021-01-02",
			layout: "2006-01-02",
			want:   time.Date(2021, time.January, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name:   "failed to parse",
			in:     "2021/01/02",
			layout: "2006-01-02",
			want:   time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParsedOrDefaultTime(tt.layout, tt.in)
			if got != tt.want {
				t.Errorf("got: %v, want: %v", got, tt.want)
			}
		})
	}
}
