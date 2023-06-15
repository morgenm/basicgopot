package server

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"net/http"

	"time"

	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/errors"
)

type FileUploadHandler struct {
	cfg       *config.Config
	uploadLog *UploadLog
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
	timeUploaded := time.Now().Format(time.UnixDate)
	uploadFilepath := filepath.Clean(filepath.Join("uploads/", timeUploaded))
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

	if h.cfg.UseVirusTotal {
		go func() {
			err := checkVirusTotal(h.cfg, h.uploadLog, uploadFilepath, hash, fileSize, handler.Filename, data)
			if err != nil {
				log.Print(err)
			}
		}()
	}

	// Add basic info about the uploaded file to the log
	if err = h.uploadLog.AddFile(uploadFilepath, handler.Filename, timeUploaded, "", hash, "Not uploaded"); err != nil {
		panic(err)
	}
}

func RunServer(cfg *config.Config) {
	// Create upload log
	uploadLog := UploadLog{
		logPath:      cfg.UploadLog,
		saveInterval: 10,
	}

	go func() {
		err := uploadLog.SaveFileLoop()
		if err != nil {
			panic(err)
		}
	}()

	// Create FileUploadHandler to add route to mux
	fileUploadHandler := FileUploadHandler{cfg, &uploadLog}

	// Create FileServer Handler to add route to mux
	fileServer := http.FileServer(http.Dir("web/static"))

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

	// Clean up
	uploadLog.quitSavingLoop = true
}
