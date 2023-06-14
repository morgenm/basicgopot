package server

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
	"github.com/morgenm/basicgopot/internal/errors"
	"github.com/morgenm/basicgopot/internal/config"
)

func checkVirusTotal(cfg *config.Config, hash string, fileSize float64, outFileName string, data []byte) error {
	// Check if valid hash
	if len(hash) != 64 {
		return &errors.InvalidHashError{}
	}
	
	alreadyOnVT := true

	// Check if on VirusTotal
	if cfg.UseVirusTotal {
		log.Print("Checking hash against VirusTotal...")

		// Make get request
		client := &http.Client{}
		requestUrl := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
		req, err := http.NewRequest("GET", requestUrl, nil)

		if !errors.CheckErr(err, "Error forming request") {
			req.Header.Add("x-apikey", cfg.VirusTotalApiKey)
			resp, err := client.Do(req)
			if !errors.CheckErr(err, "Error on GET request for VT report from hash") { // If success on GET request
				if resp.StatusCode == 401 {
					log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
					return &errors.VirusTotalAPIKeyError{}
				} else if resp.StatusCode == 404 {
					log.Print("File not yet uploaded to VirusTotal.")
					alreadyOnVT = false
				} else {
					body, err := io.ReadAll(resp.Body)
					if !errors.CheckErr(err, "Error on reading body!") && cfg.ScanOutputDir != ""{ // Successfully read body
						// Write JSON to file
						scanFilepath := filepath.Clean(filepath.Join("scans/", time.Now().Format(time.UnixDate)+" "+outFileName+".json"))
						outFile, err := os.Create(scanFilepath)
						if !errors.CheckErr(err, "Failed to create file!") { // Successfully opened file
							_, err = outFile.Write(body)
							if errors.CheckErr(err, "Error writing scan to file!") {
								return err
							}
							if errors.CheckErr(outFile.Close(), "Error closing new scan file!") {
								return err
							}
						} else {
							return err
						}

						log.Print("File already on VirusTotal, writing scan results.")
					}
				}
			}
		} else {
			return err
		}
	}

	// Upload to virus total
	if cfg.UseVirusTotal && cfg.UploadVirusTotal && !alreadyOnVT {
		// Check if file is greater than 32 MBs, which is the max upload size for VT Community
		if fileSize < 32.0 {
			log.Print("Uploading to VirusTotal...")

			// Create form file for upload
			buf := new(bytes.Buffer)
			reader := bytes.NewReader(data) // Create bytes reader for data
			writer := multipart.NewWriter(buf)
			formFile, err := writer.CreateFormFile("file", outFileName)
			if errors.CheckErr(err, "Error creating form file for upload!") {
				return err
			}

			if _, err = io.Copy(formFile, reader); err != nil {
				log.Print("error")
			}
			if errors.CheckErr(writer.Close(), "Error closing multipart form!") {
				return err
			}

			// Make POST request
			client := &http.Client{}
			requestUrl := "https://www.virustotal.com/api/v3/files"
			req, err := http.NewRequest("POST", requestUrl, buf)

			if !errors.CheckErr(err, "Error forming request") {
				req.Header.Add("accept", "application/json")
				req.Header.Add("x-apikey", cfg.VirusTotalApiKey)
				req.Header.Add("Content-Type", writer.FormDataContentType())
				req.Header.Add("boundary", writer.Boundary())

				resp, err := client.Do(req)
				if !errors.CheckErr(err, "Error on POST request for VT report from file upload") { // If success on GET request
					if resp.StatusCode == 401 {
						log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
						//return &errors.VirusTotalAPIKeyError{}
					} else {
						body, err := io.ReadAll(resp.Body)
						if !errors.CheckErr(err, "Error on reading body!") && cfg.ScanOutputDir != "" { // Successfully read body
							// Get analysis URL from response
							var decoded map[string]interface{}
							if errors.CheckErr(json.Unmarshal([]byte(body), &decoded), "Error unmarshalling JSON analysis from VirusTotal!") {
								return err
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

							if !errors.CheckErr(err, "Error forming request") {
								req.Header.Add("x-apikey", cfg.VirusTotalApiKey)
								resp, err := client.Do(req)
								if !errors.CheckErr(err, "Error on GET request for VT report from hash") { // If success on GET request
									if resp.StatusCode == 401 {
										log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
										//return &VirusTotalAPIKeyError{}
									} else if resp.StatusCode == 404 {
										log.Print("Error file analysis not found!")
									} else {
										body, err := io.ReadAll(resp.Body)
										if !errors.CheckErr(err, "Error on reading body!") { // Successfully read body
											// Write JSON to file
											scanFilename := time.Now().Format(time.UnixDate) + " " + outFileName + ".json"
											scanFilepath := filepath.Clean(filepath.Join("scans/", scanFilename))
											outFile, err := os.Create(scanFilepath)
											if errors.CheckErr(err, "Failed to create file!") { // Successfully opened file
												return err
											} else {
												_, err = outFile.Write(body)
												if errors.CheckErr(err, "Error writing scan analysis JSON to file!") {
													return err
												}
											}
											if errors.CheckErr(outFile.Close(), "Error closing the scan analysis file!") {
												return err
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
	return nil
}

type FileUploadHandler struct {
	cfg *config.Config
}

func (h FileUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set file size limit for the upload
	if errors.CheckErr(r.ParseMultipartForm(h.cfg.UploadLimitMB<<20), "Error parsing upload form!") {
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
	errors.CheckErr(err, "Failed to create file!")

	// Read uploaded file to byte array
	data, err := io.ReadAll(file)
	if errors.CheckErr(err, "Failed to read uploaded file!") {
		return
	}

	// Write to file
	_, err = outFile.Write(data)
	if errors.CheckErr(err, "Error writing the uploaded file!") {
		return
	}
	if errors.CheckErr(outFile.Close(), "Error closing the new uploaded file!") {
		return
	}

	// Inform user of success
	fmt.Fprintf(w, "File uploaded!")
	log.Print("File uploaded by user.")

	// Get file hash
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if errors.CheckErr(err, "Error getting file hash!") {
		return
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	log.Print("File hash: ", hash)

	// Get file size
	fileSize := float64(handler.Size) / (1024 * 1024) // Size in MB

	go func() {
		err := checkVirusTotal(h.cfg, hash, fileSize, uploadFilename, data)
		if err != nil {
			log.Print()
		}
	}()
}

func RunServer(cfg *config.Config) {
	// Create FileUploadHandler to add route to mux
	fileUploadHandler := FileUploadHandler{cfg}

	// Create FileServer Handler to add route to mux
	fileServer := http.FileServer(http.Dir("./static"))

	// Create mux for server
	mux := http.NewServeMux()
	mux.Handle("/upload", fileUploadHandler)
	mux.Handle("/", fileServer)

	// Create server itself
	portStr := fmt.Sprintf(":%d", cfg.ServerPort)
	server := &http.Server{
		Addr:         portStr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Listen
	log.Print("Server listening on port ", portStr)
	errors.CheckErr(server.ListenAndServe(), "Error while listening and serving!")
}
