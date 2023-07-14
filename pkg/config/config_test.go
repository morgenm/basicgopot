package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadConfigFromFileName fuzzes the fileName input.
func FuzzReadConfigFromFileName(f *testing.F) {
	f.Add("randomfile.txt")
	f.Fuzz(func(t *testing.T, fileName string) {
		cfg, err := ReadConfigFromFile(fileName)
		if err == nil || cfg != nil {
			t.Fatalf(`FuzzReadConfigFromFileName = %v, %v, want nil, nil`, cfg, err)
		}
	})
}

// FuzzReadConfigFromFileData fuzzes the file data.
func FuzzReadConfigFromFileDataValid(f *testing.F) {
	configDir := f.TempDir()
	f.Add("cooldatastring") // Data to that will be in a JSON value.

	f.Fuzz(func(t *testing.T, dataValue string) {
		fileName := filepath.Join(configDir, "config.json")

		data := map[string]interface{}{
			"key": dataValue,
		}
		jsonData, err := json.Marshal(data)
		if err != nil {
			t.Fatalf("FuzzReadConfigFromFileData could not marshal json: %s\n", err)
			return
		}

		// Open the file and write the fuzzed file data.
		file, err := os.Create(fileName)
		if err != nil {
			t.Fatalf(`FuzzReadConfigFromFileData open file failed with %v`, err)
		}
		if _, err = file.Write(jsonData); err != nil {
			t.Fatalf(`FuzzReadConfigFromFileData write file failed with %v`, err)
		}
		if err = file.Close(); err != nil {
			t.Fatalf(`FuzzReadConfigFromFileData close file failed with %v`, err)
		}

		cfg, err := ReadConfigFromFile(fileName)
		if err != nil {
			t.Fatalf(`FuzzReadConfigFromFileData = %v, %v, want cfg, nil. jsonData = %v`, cfg, err, jsonData)
		}
	})
}
