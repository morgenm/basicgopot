package server

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/webhook"
)

type WebHookCallback func([]byte)

type FileUploadHandler struct {
	cfg                    *config.Config
	uploadLog              *UploadLog
	uploadWebHookCallbacks []WebHookCallback
}

func (h FileUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set file size limit for the upload
	if err := r.ParseMultipartForm(h.cfg.UploadLimitMB << 20); err != nil {
		log.Print("Error parsing upload form!")
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

	// Read uploaded file to byte array
	data, err := io.ReadAll(file)
	if err != nil {
		log.Print("Failed to read uploaded file!")
		return
	}

	// Get time to create the upload file name, and to store it in the upload log
	timeUploaded := time.Now().Format(time.UnixDate)

	// Write file to uploads dir, if that is set in config
	uploadFilepath := ""
	if h.cfg.UploadsDir != "" {
		// Create file for writing.
		uploadFilepath = filepath.Clean(filepath.Join(h.cfg.UploadsDir, timeUploaded))
		outFile, err := os.Create(uploadFilepath)
		if err != nil {
			log.Print("Failed to create file!")
			return
		}

		// Write to file
		_, err = outFile.Write(data)
		if err != nil {
			log.Print("Error writing the uploaded file!")
			return
		}
		if err := outFile.Close(); err != nil {
			log.Print("Error closing the new uploaded file!")
			return
		}
	} else {
		// We are still using uploadFilepath as the key value to the uploadLog. So, pass uploads/... as the path.
		// This is not a great solution, but keeping this here until I think of a better key
		uploadFilepath = filepath.Clean(filepath.Join("uploads/", timeUploaded))
	}

	// Inform user of success by serving the upload success HTML file
	http.Redirect(w, r, "uploaded.html", 303)
	// fmt.Fprintf(w, "File uploaded!")
	log.Print("File uploaded by user.")

	// Get file hash
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if err != nil {
		log.Print("Error getting file hash!")
		return
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	log.Print("File hash: ", hash)

	// Check VirusTotal
	if h.cfg.UseVirusTotal {
		go func() {
			err := checkVirusTotal(h.cfg, h.uploadLog, uploadFilepath, hash, handler.Filename, data)
			if err != nil {
				log.Print(err)
			}
		}()
	}

	if len(h.cfg.UploadWebHooks) > 0 {
		go func() {
			for _, webHook := range h.uploadWebHookCallbacks {
				webHook(data)
			}
		}()
	}

	// Add basic info about the uploaded file to the log
	if err = h.uploadLog.AddFile(uploadFilepath, handler.Filename, timeUploaded, "", hash, "Not uploaded"); err != nil {
		panic(err)
	}
}

func writeWebHookResponseToFile(cfg *config.Config, reader io.ReadCloser, webHookFileName string) error {
	// Read the result
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// Write JSON to file
	webHookFilepath := filepath.Clean(filepath.Join(cfg.WebHookDir, webHookFileName))
	outFile, err := os.Create(webHookFilepath)
	if err != nil { // Failed to create file
		return err
	}
	if _, err = outFile.Write(body); err != nil {
		return err
	}
	if err = outFile.Close(); err != nil {
		return err
	}

	return nil
}

func RunServer(cfg *config.Config) {
	// Create upload log
	uploadLog := UploadLog{
		logPath:      cfg.UploadLog,
		saveInterval: 10,
	}
	if err := uploadLog.Load(); err != nil {
		panic(err)
	}

	go func() {
		err := uploadLog.SaveFileLoop()
		if err != nil {
			panic(err)
		}
	}()

	// Create Upload WebHook callbacks
	uploadWebHookCallbacks := []WebHookCallback{}
	for webHookName, webHookConfig := range cfg.UploadWebHooks {
		uploadWebHookCallbacks = append(uploadWebHookCallbacks, func(data []byte) {
			// Create the map for all the WebHook strings.
			webHookStringMap := map[string][]byte{
				"$FILE": data,
			}

			// Create WebHook.
			w := webhook.NewWebHook(webHookConfig, webHookStringMap)
			if w == nil {
				log.Print("Error creating a WebHook for file uploads!")
				return
			}

			// Execute WebHook.
			reader, err := w.Execute()
			if err != nil {
				log.Print("Error executing a WebHook for file uploads: ", err)
				return
			}

			webHookFilename := webHookName + " " + time.Now().Format(time.UnixDate)
			if err := writeWebHookResponseToFile(cfg, *reader, webHookFilename); err != nil {
				log.Print("Error writing a WebHook response to file: ", err)
			}
		})
	}

	// Create FileUploadHandler to add route to mux.
	fileUploadHandler := FileUploadHandler{cfg, &uploadLog, uploadWebHookCallbacks}

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
	if err := server.ListenAndServe(); err != nil {
		log.Print("Error while listening and serving!")
	}

	// Clean up
	uploadLog.quitSavingLoop = true
}
