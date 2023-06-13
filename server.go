package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
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
						// Write JSON to file
						scanFilepath := filepath.Clean(filepath.Join("scans/", time.Now().Format(time.UnixDate)+" "+outFileName+".json"))
						outFile, err := os.Create(scanFilepath)
						if !checkErr(err, "Failed to create file!") { // Successfully opened file
							_, err = outFile.Write(body)
							if checkErr(err, "Error writing scan to file!") {
								return
							}
						}
						if checkErr(outFile.Close(), "Error closing new scan file!") {
							return
						}

						log.Print("File already on VirusTotal, writing scan results.")
					}
				}
			}
		}
	}

	// Upload to virus total
	if config.UseVirusTotal && config.UploadVirusTotal && !alreadyOnVT {
		// Check if file is greater than 32 MBs, which is the max upload size for VT Community
		if fileSize < 32.0 {
			log.Print("Uploading to VirusTotal...")

			// Create form file for upload
			buf := new(bytes.Buffer)
			reader := bytes.NewReader(data) // Create bytes reader for data
			writer := multipart.NewWriter(buf)
			formFile, err := writer.CreateFormFile("file", outFileName)
			if checkErr(err, "Error creating form file for upload!") {
				return
			}

			if _, err = io.Copy(formFile, reader); err != nil {
				log.Print("error")
			}
			if checkErr(writer.Close(), "Error closing multipart form!") {
				return
			}

			// Make POST request
			client := &http.Client{}
			requestUrl := "https://www.virustotal.com/api/v3/files"
			req, err := http.NewRequest("POST", requestUrl, buf)

			if !checkErr(err, "Error forming request") {
				req.Header.Add("accept", "application/json")
				req.Header.Add("x-apikey", config.VirusTotalApiKey)
				req.Header.Add("Content-Type", writer.FormDataContentType())
				req.Header.Add("boundary", writer.Boundary())

				resp, err := client.Do(req)
				if !checkErr(err, "Error on POST request for VT report from file upload") { // If success on GET request
					if resp.StatusCode == 401 {
						log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
					} else {
						body, err := io.ReadAll(resp.Body)
						if !checkErr(err, "Error on reading body!") { // Successfully read body
							// Get analysis URL from response
							var decoded map[string]interface{}
							if checkErr(json.Unmarshal([]byte(body), &decoded), "Error unmarshalling JSON analysis from VirusTotal!") {
								return
							}
							jData := decoded["data"].(map[string]interface{})
							jLinks := jData["links"].(map[string]interface{})
							analysisUrl, _ := jLinks["self"].(string)

							// This isn't a great solution, but going to sleep 30 seconds for analysis to complete
							log.Print("Waiting for analysis to complete...")
							time.Sleep(30 * time.Second)

							// Make get request for analysis
							client := &http.Client{}
							req, err := http.NewRequest("GET", analysisUrl, nil)

							if !checkErr(err, "Error forming request") {
								req.Header.Add("x-apikey", config.VirusTotalApiKey)
								resp, err := client.Do(req)
								if !checkErr(err, "Error on GET request for VT report from hash") { // If success on GET request
									if resp.StatusCode == 401 {
										log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
									} else if resp.StatusCode == 404 {
										log.Print("Error file analysis not found!")
									} else {
										body, err := io.ReadAll(resp.Body)
										if !checkErr(err, "Error on reading body!") { // Successfully read body
											// Write JSON to file
											scanFilename := time.Now().Format(time.UnixDate) + " " + outFileName + ".json"
											scanFilepath := filepath.Clean(filepath.Join("scans/", scanFilename))
											outFile, err := os.Create(scanFilepath)
											if checkErr(err, "Failed to create file!") { // Successfully opened file
												return
											} else {
												_, err = outFile.Write(body)
												if checkErr(err, "Error writing scan analysis JSON to file!") {
													return
												}
											}
											if checkErr(outFile.Close(), "Error closing the scan analysis file!") {
												return
											}

											log.Print("File analysis retrieved from VirusTotal, writing scan results.")
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Update JSON upload log
}

type FileUploadHandler struct {
	config	*Config
}


func (h	FileUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set file size limit for the upload
	if checkErr(r.ParseMultipartForm(h.config.UploadLimitMB<<20), "Error parsing upload form!") {
		return
	}

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
	uploadFilename := time.Now().Format(time.UnixDate)
	uploadFilepath := filepath.Clean(filepath.Join("uploads/", uploadFilename))
	outFile, err := os.Create(uploadFilepath)
	checkErr(err, "Failed to create file!")

	// Read uploaded file to byte array
	data, err := io.ReadAll(file)
	if checkErr(err, "Failed to read uploaded file!") {
		return
	}

	// Write to file
	_, err = outFile.Write(data)
	if checkErr(err, "Error writing the uploaded file!") {
		return
	}
	if checkErr(outFile.Close(), "Error closing the new uploaded file!") {
		return
	}

	// Inform user of success
	fmt.Fprintf(w, "File uploaded!")
	log.Print("File uploaded by user.")

	// Get file hash
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if checkErr(err, "Error getting file hash!") {
		return
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	log.Print("File hash: ", hash)

	// Get file size
	fileSize := float64(handler.Size) / (1024 * 1024) // Size in MB

	go checkVirusTotal(h.config, hash, fileSize, uploadFilename, data)
}

func runServer(config *Config) {
	// Create FileUploadHandler to add route to mux
	fileUploadHandler := FileUploadHandler { config } 

	// Create FileServer Handler to add route to mux
	fileServer := http.FileServer(http.Dir("./static"))

	// Create mux for server
	mux := http.NewServeMux()
	mux.Handle("/upload", fileUploadHandler)
	mux.Handle("/", fileServer)

	// Create server itself
	portStr := fmt.Sprintf(":%d", config.ServerPort)
	server := &http.Server {
		Addr: portStr,
		Handler: mux,
		ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Listen
	log.Print("Server listening on port ", portStr)
	checkErr(server.ListenAndServe(), "Error while listening and serving!")
}
