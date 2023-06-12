package main

import "os"

func main() {
	// TODO: config set log file.
	// TODO: config set alert with email?

	// Create upload directory
	if _, err := os.Stat("uploads/"); os.IsNotExist(err) {
		if checkErr(os.Mkdir("uploads/", 0755), "Fatal error: Could not create uploads directory and it does not already exist!") {
			return
		}
	}

	// Create scans directory
	if _, err := os.Stat("scans/"); os.IsNotExist(err) {
		if checkErr(os.Mkdir("scans/", 0755), "Fatal error: Could not create scans directory and it does not already exist!") {
			return
		}
	}

	// Load config
	config, err := readConfig()
	if checkErr(err, "Error reading config.json!") {
		return
	}

	// Start the server
    runServer(config);
}