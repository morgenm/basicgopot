// Basicgopot is a simple HTTP honeypot.
// It serves an HTTP server that has an unrestricted file upload via POST requests. The server's
// functionality can be configured with the config file. It can save all files that are uploaded,
// check them against VirusTotal and upload them if they are unique, and save the analysis/scan
// to a file.
//
// Usage:
//
//	basicgopot
//
// There are no flags, as all options are defined in the config file.
package main

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/morgenm/basicgopot/internal/server"
	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/logging"
)

// Main reads the config, creates upload and scan dirs if configured to, and runs the server.
func main() {
	// Load config
	cfg, err := config.ReadConfigFromFile("config/config.json")
	if err != nil {
		log.Printf("Error reading config.json! %v", err) // Logging with log since we can't create the actual log without the config.
		return
	}

	// Create the Log
	l, err := logging.New(cfg.LogFile)
	if err != nil {
		log.Printf("Error creating log! %v", err) // Logging with log since we can't create the actual log if this failed.
		return
	}

	// Create upload directory, if specified.
	if cfg.UploadsDir != "" {
		if _, err := os.Stat(cfg.UploadsDir); os.IsNotExist(err) {
			if err := os.Mkdir(cfg.UploadsDir, 0o750); err != nil {
				l.Log("Fatal error: Could not create uploads directory and it does not already exist!")
				return
			}
		}
	}

	// Create scans directory.
	if cfg.ScanOutputDir != "" {
		if _, err := os.Stat(cfg.ScanOutputDir); os.IsNotExist(err) {
			if err := os.Mkdir(cfg.ScanOutputDir, 0o750); err != nil {
				l.Log("Fatal error: Could not create scans directory and it does not already exist!")
				return
			}
		}
	}

	// Create webhooks directory.
	if cfg.WebHookDir != "" {
		if _, err := os.Stat(cfg.WebHookDir); os.IsNotExist(err) {
			if err := os.Mkdir(cfg.WebHookDir, 0o750); err != nil {
				l.Log("Fatal error: Could not create webhooks directory and it does not already exist!")
				return
			}
		}
	}

	// Create waitgroup for servers. This is so we can implement multiple servers later.
	var wg sync.WaitGroup
	httpServer, err := server.CreateHTTPServer(cfg, l)
	if err != nil {
		l.Logf("Fatal error: Could not create HTTP server!: %v", err)
		return
	}
	wg.Add(1)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			// sig is a ^C, handle it
			httpServer.StopServer()
		}
	}()

	// Run HTTP server
	go func() {
		defer wg.Done()
		httpServer.RunServer(cfg)
	}()

	// Wait for all servers.
	wg.Wait()
}
