// Code for handling JSON config file
package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type Config struct {
	ServerPort       int
	UploadLimitMB    int64 // Upload file size limit in Megabytes
	UseVirusTotal    bool  // Whether or not to use VT
	UploadVirusTotal bool  // Whether to upload to VT
	VirusTotalApiKey string
}

func readConfig() (*Config, error) {
	f, err := os.Open("config.json")
	if checkErr(err, "Error opening config file!") {
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
	if checkErr(scanner.Err(), "Error reading config file!") {
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
