package main

import (
	"os"

	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/errors"
	"github.com/morgenm/basicgopot/internal/server"
)

func main() {
	// TODO: config set log file.
	// TODO: config set alert with email?

	// Create upload directory
	if _, err := os.Stat("uploads/"); os.IsNotExist(err) {
		if errors.CheckErr(os.Mkdir("uploads/", 0o750), "Fatal error: Could not create uploads directory and it does not already exist!") {
			return
		}
	}

	// Create scans directory
	if _, err := os.Stat("scans/"); os.IsNotExist(err) {
		if errors.CheckErr(os.Mkdir("scans/", 0o750), "Fatal error: Could not create scans directory and it does not already exist!") {
			return
		}
	}

	// Load config
	cfg, err := config.ReadConfig("config.json")
	if errors.CheckErr(err, "Error reading config.json!") {
		return
	}

	// Start the server
	server.RunServer(cfg)
}
