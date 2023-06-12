package main

import (
	"fmt"
    "net/http"
	"log"
	"os"
	"time"
	"crypto/sha256"
	"io"
)

func checkVirusTotal(config *Config, hash string, fileSize float64, outFileName string, data []byte) {
	alreadyOnVT := true

	// Check if on VirusTotal
	if config.UseVirusTotal {
		log.Print("Checking hash against VirusTotal...")

		// Make get request
		client := &http.Client{}
		requestUrl := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
		req, err := http.NewRequest("GET", requestUrl, nil)

		if !checkErr(err, "Error forming request") {
			req.Header.Add("x-apikey", config.VirusTotalApiKey)
			resp, err := client.Do(req)
			if !checkErr(err, "Error on GET request for VT report from hash") { // If success on GET request
				if resp.StatusCode == 401 {
					log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
				} else if resp.StatusCode == 404 {
					log.Print("File not yet uploaded to VirusTotal.")
					alreadyOnVT = false
				} else {
					body, err := io.ReadAll(resp.Body)
					if !checkErr(err, "Error on reading body!") { // Successfully read body
						
					}

					// Write JSON to file
					scanFilename := "scans/" + time.Now().Format(time.UnixDate) + " " + outFileName+".json";
					outFile, err := os.Create(scanFilename)
					if !checkErr(err, "Failed to create file!") { // Successfully opened file
						outFile.Write(body)
					}
					defer outFile.Close()
				}
			}
		}
	}

	// Upload to virus total
	if config.UseVirusTotal && config.UploadVirusTotal && !alreadyOnVT {
		// Check if file is greater than 32 MBs, which is the max upload size for VT Community
		if fileSize < 32.0 {
			log.Print("Uploading to VirusTotal...")
		}
	}

	// Update JSON upload log
}

func (config *Config) fileUploadHandler(w http.ResponseWriter, r *http.Request) {
	// Set file size limit for the upload
	r.ParseMultipartForm(config.UploadLimitMB << 20)

	// Get file
	file, handler, err := r.FormFile("fileupload")
	if err != nil {
		log.Print("File upload from user failed! ", err)
		fmt.Fprintf(w, "File upload failed!")
		return
	}
	defer file.Close()
	log.Print("File being uploaded by user...")

	// Create file for writing. TODO: Make writing optional in config
	uploadFilename := time.Now().Format(time.UnixDate) + " " + handler.Filename;
	outFile, err := os.Create("uploads/" + uploadFilename)
	checkErr(err, "Failed to create file!")
	defer outFile.Close()

	// Read uploaded file to byte array
	data, err := io.ReadAll(file)
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

	// Get file size
	fileSize := float64(handler.Size) / (1024* 1024) // Size in MB

	go checkVirusTotal(config, hash, fileSize, uploadFilename, data)
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

