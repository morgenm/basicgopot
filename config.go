// Code for handling JSON config file
package main

import(
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	ServerPort			int
	UseVirusTotal		bool // Whether or not to use VT
	UploadVirusTotal	bool // Whether to upload to VT
	VirusTotalApiKey	string
}

func readConfig() (*Config, error) {
	data, err := ioutil.ReadFile("config.json")
	if err != nil {
		return nil, err
	}

	var config Config

	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}