package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/errors"
)

func checkHashVirusTotal(apiKey string, hash string, scanOutputDir string, outFileName string, scanFilepath string) (bool, error) {
	// Make get request
	client := &http.Client{}
	requestUrl := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil { //
		return false, err
	}

	req.Header.Add("x-apikey", apiKey)
	resp, err := client.Do(req)
	if err != nil { // Failed GET Request
		return false, err
	}

	// Check status codes to see if auth succeeded and if hash present on VT
	if resp.StatusCode == 401 {
		log.Print("Error: Auth with VirusTotal failed! Check that your API key in the config file is valid.")
		return false, &errors.VirusTotalAPIKeyError{}
	} else if resp.StatusCode == 404 { // Hash not present
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	if scanOutputDir == "" { // Successfully read the VirusTotal JSON data, but won't write the scan file
		return true, nil
	}

	// Write JSON to file
	outFile, err := os.Create(scanFilepath)
	if err != nil {
		log.Print("Failed creating the file: ", scanFilepath)
		return true, err
	}
	_, err = outFile.Write(body)
	if err != nil {
		return true, err
	}
	if err = outFile.Close(); err != nil {
		return true, err
	}

	log.Print("File already on VirusTotal, writing scan results.")
	return true, nil
}

func uploadFileVirusTotal(apiKey string, hash string, fileSize float64, scanOutputDir string, outFileName string, data []byte) error {
	// Check if file is greater than 32 MBs, which is the max upload size for VT Community
	if fileSize > 32.0 {
		return &errors.FileTooBig{}
	}

	log.Print("Uploading to VirusTotal...")

	// Create form file for upload
	buf := new(bytes.Buffer)
	reader := bytes.NewReader(data) // Create bytes reader for data
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("file", outFileName)
	if err != nil {
		return err
	}

	if _, err = io.Copy(formFile, reader); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}

	// Make POST request
	client := &http.Client{}
	requestUrl := "https://www.virustotal.com/api/v3/files"
	req, err := http.NewRequest("POST", requestUrl, buf)
	if err != nil {
		return err
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("boundary", writer.Boundary())

	resp, err := client.Do(req)
	if err != nil {
		log.Print("Error on POST request for uploading file to VT!")
		return err
	}

	if resp.StatusCode == 401 {
		log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
		return &errors.VirusTotalAPIKeyError{}
	}

	// Read the body of the response so we can grab the analysis URL
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if scanOutputDir == "" { // If we are not outputting scans, we are done here
		return nil
	}

	// Get analysis URL from response so we can download the report
	var decoded map[string]interface{}
	if err = json.Unmarshal([]byte(body), &decoded); err != nil {
		return err
	}
	jData := decoded["data"].(map[string]interface{})
	jLinks := jData["links"].(map[string]interface{})
	analysisUrl, _ := jLinks["self"].(string)

	// This isn't a great solution, but going to sleep 30 seconds for analysis to complete
	log.Print("Waiting for analysis to complete...")
	time.Sleep(30 * time.Second)

	// Make get request for analysis
	client = &http.Client{}
	req, err = http.NewRequest("GET", analysisUrl, nil)
	if err != nil {
		return err
	}
	req.Header.Add("x-apikey", apiKey)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}

	// Check what our response is and make sure we can start reading the analysis
	if resp.StatusCode == 401 {
		log.Print("Error: VirusTotal authentication failed! Check your API key in config.json!")
		return &errors.VirusTotalAPIKeyError{}
	} else if resp.StatusCode == 404 {
		log.Print("Error file analysis not found!")
		return &errors.VirusTotalAnalysisNotFound{}
	}

	if scanOutputDir == "" { // We are done here if we are not outputting scans to file
		return nil
	}

	// Read the analysis file
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Write JSON to file
	scanFilename := time.Now().Format(time.UnixDate) + " " + outFileName + ".json"
	scanFilepath := filepath.Clean(filepath.Join(scanOutputDir, scanFilename))
	outFile, err := os.Create(scanFilepath)
	if err != nil { // Failed to create file
		return err
	}
	if _, err = outFile.Write(body); err != nil {
		return err
	}
	if err = outFile.Close(); err != nil {
		return err
	}

	log.Print("File analysis retrieved from VirusTotal, writing scan results.")
	return nil
}

func checkVirusTotal(cfg *config.Config, uploadLog *UploadLog, uploadFilepath string, hash string, fileSize float64, outFileName string, data []byte) error {
	// Check if valid hash
	if len(hash) != 64 {
		return &errors.InvalidHashError{}
	}

	// Check if on VirusTotal
	log.Print("Checking hash against VirusTotal...")
	scanFilepath := filepath.Clean(filepath.Join(cfg.ScanOutputDir, time.Now().Format(time.UnixDate)+" "+outFileName+".json"))
	alreadyOnVT, err := checkHashVirusTotal(cfg.VirusTotalApiKey, hash, cfg.ScanOutputDir, outFileName, scanFilepath)
	if err != nil {
		return err
	} else if alreadyOnVT {
		if err = uploadLog.UpdateFileScan(uploadFilepath, scanFilepath, "Scan"); err != nil {
			return err
		}
		return nil
	}

	// Upload to VirusTotal, if configured to
	if !cfg.UploadVirusTotal {
		return nil
	}
	err = uploadFileVirusTotal(cfg.VirusTotalApiKey, hash, fileSize, cfg.ScanOutputDir, outFileName, data)
	if err != nil {
		return err
	}
	if err = uploadLog.UpdateFileScan(uploadFilepath, scanFilepath, "Analysis"); err != nil {
		return err
	}

	return nil
}
