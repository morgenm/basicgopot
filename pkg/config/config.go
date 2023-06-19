// The config package contains code for loading basicgopot configuration.
package config

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	ServerPort       int
	UploadLimitMB    int64 // Upload file size limit in Megabytes.
	UseVirusTotal    bool  // Whether or not to use VT.
	UploadVirusTotal bool  // Whether to upload to VT.
	VirusTotalApiKey string
	ScanOutputDir    string // Directory to output VT scans, leave empty if no output scans are wanted.
	UploadsDir       string // Directory to output all files uploaded to server, leave empty if you don't want to save any uploads.
	UploadLog        string // JSON file to output log detailing upload file data.
}

// loadConfig takes a slice of bytes and outputs the config that is read from those (*Config, nil) on success,
// nil, error on failure.
func loadConfig(configData []byte) (*Config, error) {
	var config Config

	err := json.Unmarshal(configData, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// ReadConfigFromFile takes a file path as a string and returns *Config, nil on success and nil, error on failure.
func ReadConfigFromFile(fileName string) (*Config, error) {
	f, err := os.Open(filepath.Clean(fileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read the config file
	scanner := bufio.NewScanner(f)
	var data []byte

	for scanner.Scan() { // Reading lime-by-line
		line := scanner.Bytes()
		data = append(data, line...)
		data = append(data, '\n')
	}
	if err != nil {
		return nil, err
	}

	return loadConfig(data)
}
