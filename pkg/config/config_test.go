package config

import (
	"testing"
)

// FuzzReadConfigFromFile fuzzes the fileName input.
func FuzzReadConfigFromFile(f *testing.F) {
	f.Add("randomfile.txt")
	f.Fuzz(func(t *testing.T, fileName string) {
		cfg, err := ReadConfigFromFile(fileName)
		if err == nil || cfg != nil {
			t.Fatalf(`FuzzLoadConfig = %v, %v, want nil, nil`, cfg, err)
		}
	})
}
