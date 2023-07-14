// The config package contains code for loading basicgopot configuration.
package config

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/morgenm/basicgopot/pkg/errors"
)

type WebHookConfig struct {
	URL     string            // URL that the request will be made to.
	Method  string            // HTTP method for the request.
	Headers map[string]string // HTTP headers for the request.
	Forms   map[string]string // Forms to be sent in the request if it has method POST.
}

type Config struct {
	ServerPort       int
	LogFile          string                   // Filepath to log to. If set to "", will just log to stdout
	UploadLimitMB    int64                    // Upload file size limit in Megabytes.
	UseVirusTotal    bool                     // Whether or not to use VT.
	UploadVirusTotal bool                     // Whether to upload to VT.
	VirusTotalApiKey string                   // VirusTotal API key for checking hashes and uploading files
	ScanOutputDir    string                   // Directory to output VT scans, leave empty if no output scans are wanted.
	UploadsDir       string                   // Directory to output all files uploaded to server, leave empty if you don't want to save any uploads.
	UploadLog        string                   // JSON file to output log detailing upload file data.
	WebHookDir       string                   // Directory to save results from WebHook requests.
	UploadWebHooks   map[string]WebHookConfig // User-defined WebHooks.
}

// loadConfig takes a slice of bytes and outputs the config that is read from those (*Config, nil) on success,
// nil, error on failure.
func loadConfig(configData []byte) (*Config, error) {
	var config Config

	err := json.Unmarshal(configData, &config)
	if err != nil {
		return nil, err
	}

	// Validate that all the WebHooks have a valid method.
	for _, webHook := range config.UploadWebHooks {
		if webHook.Method != "POST" {
			return nil, &errors.WebHookInvalidMethod{}
		}
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
