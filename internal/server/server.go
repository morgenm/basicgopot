package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/logging"
	"github.com/morgenm/basicgopot/pkg/webhook"
)

type WebHookCallback func([]byte, string)

type FileUploadHandler struct {
	cfg                    *config.Config
	uploadLog              *UploadLog
	uploadWebHookCallbacks []WebHookCallback
	log                    *logging.Log
}

type HTTPServer struct {
	srv       *http.Server
	uploadLog *UploadLog
	log       *logging.Log
}

// createScanWriter will create a scan file based on the current time and will return the writer
// scanfilepath and nil on success, nil "" and error on failure.
func createScanWriter(cfg *config.Config) (io.WriteCloser, string, error) {
	scanFilename := time.Now().Format(time.UnixDate) + ".json"
	scanFilepath := filepath.Clean(filepath.Join(cfg.ScanOutputDir, scanFilename))
	outFile, err := os.Create(scanFilepath)
	if err != nil { // Failed to create file
		return nil, "", err
	}

	return outFile, scanFilepath, nil
}

func (h FileUploadHandler) handleUploadFile(handler *multipart.FileHeader, data []byte) {
	// Get time to create the upload file name, and to store it in the upload log
	timeUploaded := time.Now().Format(time.UnixDate)

	// Write file to uploads dir, if that is set in config
	uploadFilepath := ""
	if h.cfg.UploadsDir != "" {
		// Create file for writing.
		uploadFilepath = filepath.Clean(filepath.Join(h.cfg.UploadsDir, timeUploaded))
		outFile, err := os.Create(uploadFilepath)
		if err != nil {
			h.log.Log("Failed to create file!")
			return
		}

		// Write to file
		_, err = outFile.Write(data)
		if err != nil {
			h.log.Log("Error writing the uploaded file!")
			return
		}
		if err := outFile.Close(); err != nil {
			h.log.Log("Error closing the new uploaded file!")
			return
		}
	} else {
		// We are still using uploadFilepath as the key value to the uploadLog. So, pass uploads/... as the path.
		// This is not a great solution, but keeping this here until I think of a better key
		uploadFilepath = filepath.Clean(filepath.Join("uploads/", timeUploaded))
	}

	// Get file hash
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		h.log.Log("Error getting file hash!")
		return
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	h.log.Log("File hash: ", hash)

	// Add basic info about the uploaded file to the log
	if err = h.uploadLog.AddFile(uploadFilepath, handler.Filename, timeUploaded, "", hash, "Not uploaded"); err != nil {
		panic(err)
	}

	// Wait for upload hooks and VT goroutine
	var wg sync.WaitGroup
	if h.cfg.UseVirusTotal {
		wg.Add(1)
	}
	if len(h.cfg.UploadWebHooks) > 0 {
		wg.Add(1)
	}

	// Check VirusTotal
	if h.cfg.UseVirusTotal {
		go func() {
			var scanWriter io.WriteCloser
			var scanFilepath string
			if h.cfg.ScanOutputDir == "" {
				scanWriter = nil
			} else {
				if scanWriter, scanFilepath, err = createScanWriter(h.cfg); err != nil {
					h.log.Log(err)
					wg.Done()
					return
				}
			}

			err := checkVirusTotal(h.cfg, h.log, h.uploadLog, scanWriter, scanFilepath, uploadFilepath, hash, handler.Filename, data)
			if err != nil {
				h.log.Log(err)
			}

			wg.Done()
		}()
	}

	if len(h.cfg.UploadWebHooks) > 0 {
		go func() {
			for _, webHook := range h.uploadWebHookCallbacks {
				webHook(data, uploadFilepath)
			}
			wg.Done()
		}()
	}

	wg.Wait()
}

func (h FileUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set file size limit for the upload
	if err := r.ParseMultipartForm(h.cfg.UploadLimitMB << 20); err != nil {
		h.log.Log("Error parsing upload form!")
		return
	}

	// Get file
	file, handler, err := r.FormFile("fileupload")
	if err != nil {
		h.log.Log("File upload from user failed! ", err)
		fmt.Fprintf(w, "File upload failed!")
		return
	}
	defer file.Close()
	h.log.Log("File being uploaded by user...")

	// Read uploaded file to byte array
	data, err := io.ReadAll(file)
	if err != nil {
		h.log.Log("Failed to read uploaded file!")
		return
	}

	// Inform user of success by serving the upload success HTML file
	http.Redirect(w, r, "uploaded.html", 303)
	// fmt.Fprintf(w, "File uploaded!")
	h.log.Log("File uploaded by user.")

	h.handleUploadFile(handler, data)
}

func writeWebHookResponseToFile(cfg *config.Config, reader io.Reader, webHookFileName string) error {
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

// CreateHTTPServer returns a pointer to a new HTTPServer. Takes config as input in order to define the upload log and WebHooks.
func CreateHTTPServer(cfg *config.Config, log *logging.Log) (*HTTPServer, error) {
	var httpServer HTTPServer

	// Create upload log
	httpServer.uploadLog = &UploadLog{
		logPath:      cfg.UploadLog,
		saveInterval: 10,
	}
	if err := httpServer.uploadLog.Load(); err != nil {
		return nil, err
	}

	// Define logger
	httpServer.log = log

	// Create Upload WebHook callbacks
	uploadWebHookCallbacks := []WebHookCallback{}
	for webHookName, webHookConfig := range cfg.UploadWebHooks {
		uploadWebHookCallbacks = append(uploadWebHookCallbacks, func(data []byte, uploadPath string) {
			// Create the map for all the WebHook strings.
			webHookStringMap := map[string][]byte{
				"$FILE": data,
			}

			// Create WebHook.
			w := webhook.NewWebHook(webHookConfig, webHookStringMap)
			if w == nil {
				httpServer.log.Log("Error creating a WebHook for file uploads!")
				return
			}

			// Execute WebHook.
			reader, err := w.Execute()
			if err != nil {
				httpServer.log.Log("Error executing a WebHook for file uploads: ", err)
				return
			}

			webHookFilename := webHookName + " " + time.Now().Format(time.UnixDate)
			if err := writeWebHookResponseToFile(cfg, *reader, webHookFilename); err != nil {
				httpServer.log.Log("Error writing a WebHook response to file: ", err)
				return
			}

			if err = httpServer.uploadLog.UpdateAddWebHookPath(uploadPath, webHookName, webHookFilename); err != nil {
				httpServer.log.Log("Error updating UploadLog with WebHook filepath!")
				return
			}
		})
	}

	// Create FileUploadHandler to add route to mux.
	fileUploadHandler := FileUploadHandler{cfg, httpServer.uploadLog, uploadWebHookCallbacks, log}

	// Create FileServer Handler to add route to mux
	fileServer := http.FileServer(http.Dir("web/static"))

	// Create mux for server
	mux := http.NewServeMux()
	mux.Handle("/upload", fileUploadHandler)
	mux.Handle("/", fileServer)

	// Create server itself
	portStr := fmt.Sprintf(":%d", cfg.ServerPort)

	httpServer.srv = &http.Server{
		Addr:         portStr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return &httpServer, nil
}

func (httpServer HTTPServer) RunServer(cfg *config.Config) {
	// Run upload log save loop
	go func() {
		err := httpServer.uploadLog.SaveFileLoop()
		if err != nil {
			panic(err)
		}
	}()

	// Listen
	httpServer.log.Log("Server listening on ", httpServer.srv.Addr)
	expectedErr := http.ErrServerClosed
	if err := httpServer.srv.ListenAndServe(); err != nil && err.Error() != expectedErr.Error() {
		httpServer.log.Log("Error while listening and serving!: ", err)
	}
}

func (httpServer HTTPServer) StopServer() {
	httpServer.log.Log("Shutting down server...")

	httpServer.uploadLog.StopSaveFileLoop() // Stop upload log

	if httpServer.srv == nil {
		httpServer.log.Log("Fatal error: HTTP server is nil!")
		return
	}

	if err := httpServer.srv.Shutdown(context.Background()); err != nil {
		httpServer.log.Log("Error while shutting down server: ", err)
	}
}
