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

func checkErr(err error, outString string) bool {
	if err != nil {
		log.Print(outString, " ", err)
		return true
	} else {
		return false
	}
}

func fileUploadHandler(w http.ResponseWriter, r *http.Request) {
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


	// Check if on VirusTotal. TODO: Make VT optional

	// Upload to virus total. TODO: Make file upload optional

	// Update JSON upload log

}

func main() {
	// TODO: create upload directory 

    server := http.FileServer(http.Dir("./static"))
	http.Handle("/", server)

	// File upload handler setup
	http.HandleFunc("/upload", fileUploadHandler)


	port := ":8080"
	log.Print("Server listening on port ", port)
	http.ListenAndServe(port, nil)
}