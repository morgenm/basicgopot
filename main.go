package main

func main() {
	// TODO: create upload directory and scans dir
	// TODO: config set log file. config set output json file
	// TODO: config set alert with email?

	// Load config
	config, err := readConfig()
	if checkErr(err, "Error reading config.json!") {
		return
	}

	// Start the server
    runServer(config);
}