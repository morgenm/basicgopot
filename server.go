package main

import (
	"fmt"
    "net/http"
	"log"
	"io/ioutil"
	"os"
	"time"
	"crypto/sha256"
)

func (config *Config) fileUploadHandler(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("fileupload")
	if err != nil {
		log.Print("File upload from user failed! ", err)
		fmt.Fprintf(w, "File upload failed!")
		return
	}
	defer file.Close()
	log.Print("File being uploaded by user...")

	// Create file for writing. TODO: Make writing optional in config
	uploadFilename := "uploads/" + time.Now().Format(time.UnixDate) + " " + handler.Filename;
	outFile, err := os.Create(uploadFilename)
	checkErr(err, "Failed to create file!")
	defer outFile.Close()

	// Read uploaded file to byte array
	data, err := ioutil.ReadAll(file)
	if checkErr(err, "Failed to read uploaded file!")  {
		return
	}

	// Write to file
	outFile.Write(data)

	// Inform user of success
	fmt.Fprintf(w, "File uploaded!")
	log.Print("File uploaded by user.")

	// Get file hash
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if checkErr(err, "Error getting file hash!")  {
		return
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	log.Print("File hash: ", hash)


	// Check if on VirusTotal
	if config.UseVirusTotal {
		log.Print("Checking hash against VirusTotal...")
	}

	// Upload to virus total
	if config.UseVirusTotal && config.UploadVirusTotal {
		log.Print("Uploading to VirusTotal...")
	}

	// Update JSON upload log

}

func runServer(config *Config) {
	server := http.FileServer(http.Dir("./static"))
	http.Handle("/", server)

	// File upload handler setup
	http.HandleFunc("/upload", config.fileUploadHandler)

	// Listen
	portStr := fmt.Sprintf(":%d", config.ServerPort)
	log.Print("Server listening on port ", portStr)
	http.ListenAndServe(portStr, nil)
}

