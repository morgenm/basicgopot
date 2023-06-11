package main

import (
	"fmt"
    "net/http"
	"log"
	"io/ioutil"
	"os"
	"time"
)

func checkErr(err error, outString string) {
	if err != nil {
		log.Print(outString, " ", err)
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

	// Create file for writing. Make writing optional in config
	uploadFilename := "uploads/" + time.Now().Format(time.UnixDate) + " " + handler.Filename;
	outFile, err := os.Create(uploadFilename)
	checkErr(err, "Failed to create file!")
	defer outFile.Close()

	// Read uploaded file to byte array
	data, err := ioutil.ReadAll(file)
	checkErr(err, "Failed to read uploaded file!")

	// Write to file
	outFile.Write(data)

	// Inform user of success
	fmt.Fprintf(w, "File uploaded!")
	log.Print("File uploaded by user.")

	// Upload to virus total

	// Update JSON upload log

}

func main() {
    server := http.FileServer(http.Dir("./static"))
	http.Handle("/", server)

	// File upload handler setup
	http.HandleFunc("/upload", fileUploadHandler)


	port := ":8080"
	log.Print("Server listening on port ", port)
	http.ListenAndServe(port, nil)
}