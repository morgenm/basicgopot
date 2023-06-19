// The vt package implements routines for checking a file hash against VirusTotal and for uploading a file to VirusTotal.
package vt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"

	"github.com/morgenm/basicgopot/pkg/errors"
)

// isValidSha256 checks if a given string is a hash in sha256 format.
func isValidSha256(hash string) bool {
	regex := regexp.MustCompile("^[a-fA-F0-9]{64}$")
	return regex.MatchString(hash)
}

// CheckHashVirusTotal will send a file hash to VirusTotal and return the scan output as (*io.ReadCloser, nil) if the file
// has already been uploaded to VirusTotal. Will return (nil, error) on failure.
func CheckHashVirusTotal(apiKey string, hash string) (*io.ReadCloser, error) {
	if !isValidSha256(hash) {
		return nil, &errors.InvalidHashError{}
	}

	// Make get request
	client := &http.Client{}
	requestUrl := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil { //
		return nil, err
	}

	req.Header.Add("x-apikey", apiKey)
	resp, err := client.Do(req)
	if err != nil { // Failed GET Request
		return nil, err
	}

	// Check status codes to see if auth succeeded and if hash present on VT
	if resp.StatusCode == 401 {
		return nil, &errors.VirusTotalAPIKeyError{}
	} else if resp.StatusCode == 404 { // Hash not present
		return nil, nil
	}

	return &resp.Body, nil
}

// UploadFileVirusTotal will upload a file to VirusTotal and will return the analysis as (*io.ReadCloser, nil) on success. Will return
// (nil, error) on failure.
func UploadFileVirusTotal(apiKey string, fileName string, data []byte) (*io.ReadCloser, error) {
	// Check if file is greater than 32 MBs, which is the max upload size for VT Community
	fileSize := len(data) / (1024 * 1024)
	if fileSize > 32.0 {
		return nil, &errors.FileTooBig{}
	}

	// Create form file for upload
	buf := new(bytes.Buffer)
	reader := bytes.NewReader(data) // Create bytes reader for data
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return nil, err
	}

	if _, err = io.Copy(formFile, reader); err != nil {
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}

	// Make POST request
	client := &http.Client{}
	requestUrl := "https://www.virustotal.com/api/v3/files"
	req, err := http.NewRequest("POST", requestUrl, buf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("boundary", writer.Boundary())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		return nil, &errors.VirusTotalAPIKeyError{}
	}

	// Get analysis URL from response so we can download the report
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded map[string]interface{}
	if err = json.Unmarshal([]byte(body), &decoded); err != nil {
		return nil, err
	}
	jData := decoded["data"].(map[string]interface{})
	jLinks := jData["links"].(map[string]interface{})
	analysisUrl, _ := jLinks["self"].(string)

	// Make get request for analysis
	client = &http.Client{}
	req, err = http.NewRequest("GET", analysisUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("x-apikey", apiKey)
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}

	// Check what our response is and make sure we can start reading the analysis
	if resp.StatusCode == 401 {
		return nil, &errors.VirusTotalAPIKeyError{}
	} else if resp.StatusCode == 404 {
		return nil, &errors.VirusTotalAnalysisNotFound{}
	}

	return &resp.Body, nil
}
