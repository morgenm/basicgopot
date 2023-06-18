package main

import (
	"os"

	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/server"
	"github.com/morgenm/basicgopot/pkg/errors"
)

func main() {
	// Load config
	cfg, err := config.ReadConfig("config/config.json")
	if errors.CheckErr(err, "Error reading config.json!") {
		return
	}

	// Create upload directory, if specified
	if cfg.UploadsDir != "" {
		if _, err := os.Stat(cfg.UploadsDir); os.IsNotExist(err) {
			if errors.CheckErr(os.Mkdir(cfg.UploadsDir, 0o750), "Fatal error: Could not create uploads directory and it does not already exist!") {
				return
			}
		}
	}

	// Create scans directory
	if cfg.ScanOutputDir != "" {
		if _, err := os.Stat(cfg.ScanOutputDir); os.IsNotExist(err) {
			if errors.CheckErr(os.Mkdir(cfg.ScanOutputDir, 0o750), "Fatal error: Could not create scans directory and it does not already exist!") {
				return
			}
		}
	}

	// Start the server
	server.RunServer(cfg)
}
