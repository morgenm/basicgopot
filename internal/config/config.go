// Code for handling JSON config file
package config

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"github.com/morgenm/basicgopot/internal/errors"
)

type Config struct {
	ServerPort       int
	UploadLimitMB    int64 // Upload file size limit in Megabytes
	UseVirusTotal    bool  // Whether or not to use VT
	UploadVirusTotal bool  // Whether to upload to VT
	VirusTotalApiKey string
	ScanOutputDir	 string // Directory to output VT scans, leave empty if no output scans are wanted
}

func ReadConfig(filename string) (*Config, error) {
	f, err := os.Open(filepath.Clean(filename))
	if errors.CheckErr(err, "Error opening config file!") {
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
	if errors.CheckErr(scanner.Err(), "Error reading config file!") {
		return nil, err
	}

	// Create the config from the file
	var config Config

	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
