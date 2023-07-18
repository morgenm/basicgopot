package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
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
	uploadFailedHTMLData   []byte
	uploadSuccessHTMLData  []byte
}

// FileServerHandler just wraps Go's FileServer with logging.
type FileServerHandler struct {
	fileServer  http.Handler
	log         *logging.Log
	fsys        *fs.FS
	missingData []byte // Data for 404
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

func GetUploadFilePath(uploadLog *UploadLog, uploadsDir string, timeUploaded string) string {
	var uploadFilepath string

	if uploadsDir != "" {
		// Uploads directory exists, so use that.
		uploadFilepath = filepath.Clean(filepath.Join(uploadsDir, timeUploaded))
	} else {
		// We are still using uploadFilepath as the key value to the uploadLog. So, pass uploads/... as the path.
		uploadFilepath = filepath.Clean(filepath.Join("uploads/", timeUploaded))
	}

	// If another file is in the log with the same name (uploaded at same time as another file),
	// append a counter to the end of the filepath to make the name unique.
	counter := 1
	originalUploadFilepath := uploadFilepath
	for {
		if !uploadLog.IsInLog(uploadFilepath) {
			break
		} else {
			uploadFilepath = originalUploadFilepath + fmt.Sprintf(" - %d", counter)
			counter += 1
		}
	}

	return uploadFilepath
}

func (h FileUploadHandler) handleUploadFile(handler *multipart.FileHeader, uploaderIP string, data []byte) {
	// Get time to create the upload file name, and to store it in the upload log
	timeUploaded := time.Now().Format(time.UnixDate)

	// Get upload filepath based on upload directory and time uploaded.
	uploadFilepath := GetUploadFilePath(h.uploadLog, h.cfg.UploadsDir, timeUploaded)

	// Save file to upload dir if it exists.
	if h.cfg.UploadsDir != "" {
		outFile, err := os.Create(filepath.Clean(uploadFilepath))
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
	if err = h.uploadLog.AddFile(uploadFilepath, uploaderIP, handler.Filename, timeUploaded, "", hash, "Not uploaded"); err != nil {
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
	h.log.Logf("File being uploaded by %s...", r.RemoteAddr)

	// Make sure this is a POST request
	if r.Method != "POST" {
		http.Error(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	// Set maximum upload size
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.UploadLimitMB<<20)

	// Max memory used by server here is 2GB
	if err := r.ParseMultipartForm(2048 << 20); err != nil {
		h.log.Logf("Error parsing upload form from %s! %v. Max file size = %d MB", r.RemoteAddr, err, h.cfg.UploadLimitMB)

		w.WriteHeader(400)
		_, err := w.Write(h.uploadFailedHTMLData)
		if err != nil {
			h.log.Logf("Error: could not serve file upload failure HTML file. %v", err)
			_, err = w.Write([]byte("File upload failed!"))
			if err != nil {
				h.log.Logf("Error: could not serve file upload failure string. %v", err)
			}
		}

		return
	}

	// Inform user of success by serving the upload success HTML file
	w.WriteHeader(200)
	_, err := w.Write(h.uploadSuccessHTMLData)
	h.log.Logf("File uploaded by %s.", r.RemoteAddr)
	if err != nil {
		h.log.Logf("Error: could not serve file upload success HTML file. %v", err)
		_, err = w.Write([]byte("File upload succeeded!"))
		if err != nil {
			h.log.Logf("Error: could not serve file upload success string. %v", err)
		}
	}

	// Get file data and handler from the upload form.
	file, handler, err := r.FormFile("fileupload")
	if err != nil {
		h.log.Logf("File upload from %s failed!: %v", r.RemoteAddr, err)
		return
	}
	defer file.Close()

	// Read uploaded file to byte array
	data, err := io.ReadAll(file)
	if err != nil {
		h.log.Logf("Failed to read uploaded file from %s! %v", r.RemoteAddr, err)
		return
	}

	h.handleUploadFile(handler, r.RemoteAddr, data)
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

// ServeHTTP logs the given request and servers the requested file. This handles all requests that are not
// handled by the upload handler. Additionally, this will serve the 404 and upload-failed pages with their
// respective status codes.
func (h FileServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.log.Logf("%s request at %s from %s", r.Method, r.URL, r.RemoteAddr)

	// Make sure requested file exists, if not return 404.
	if filepath.Clean(r.URL.Path) == "/" {
		h.fileServer.ServeHTTP(w, r) // Serve index page.
	} else if _, err := fs.Stat(*h.fsys, filepath.Clean(r.URL.Path[1:])); os.IsNotExist(err) { // Stat file. Remove first ('/').
		// Return a 404 page
		w.WriteHeader(404)
		if _, err = w.Write(h.missingData); err != nil {
			h.log.Logf("Error writing 404 page! %v", err)
		}
	} else if err != nil {
		h.log.Logf("%v %v %s", err, *h.fsys, filepath.Clean(r.URL.Path)) // Error performing stat.
		w.WriteHeader(http.StatusBadRequest)
	} else {
		h.fileServer.ServeHTTP(w, r) // File exists, serve it.
	}
}

// GetPageData looks to see if a given HTML file is defined, and returns the HTML on success.
// If it doesn't exist, returns the default string.
func GetPageData(pageFilepath string, defaultString string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(pageFilepath))

	var pageData []byte
	if os.IsNotExist(err) {
		pageData = []byte(defaultString)
	} else if err != nil {
		return nil, err
	} else {
		defer f.Close()

		// Get file size.
		stat, err := f.Stat()
		if err != nil {
			return nil, err
		}

		// Read the uploadLog file
		pageData = make([]byte, stat.Size())

		if _, err = bufio.NewReader(f).Read(pageData); err != nil {
			return nil, err
		}
	}
	return pageData, nil
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

	// Load upload failed data from file for the upload handler. Instead of redirecting,
	// we are serving the data directly to prevent any connection reset errors.
	// If file doesn't exist, default to a failure string.
	uploadFailedData, err := GetPageData("web/static/upload-failed.html", "File upload failed!")
	if err != nil {
		return nil, err
	}

	// Load upload success data from file for the upload handler. Instead of redirecting,
	// we are serving the data directly to prevent any connection reset errors.
	// If file doesn't exist, default to a success string.
	uploadSuccessData, err := GetPageData("web/static/uploaded.html", "File upload succeeded!")
	if err != nil {
		return nil, err
	}

	// Load 404 page data.
	missingData, err := GetPageData("web/static/404.html", "404: Page not Found!")
	if err != nil {
		return nil, err
	}

	// Create FileUploadHandler to add route to mux.
	fileUploadHandler := FileUploadHandler{
		cfg:                    cfg,
		uploadLog:              httpServer.uploadLog,
		uploadWebHookCallbacks: uploadWebHookCallbacks,
		log:                    log,
		uploadFailedHTMLData:   uploadFailedData,
		uploadSuccessHTMLData:  uploadSuccessData,
	}

	// Create FileServer Handler to add route to mux
	fsys := os.DirFS("web/static")
	fileServer := FileServerHandler{http.FileServer(http.FS(fsys)), log, &fsys, missingData}

	// Create mux for server
	mux := http.NewServeMux()
	mux.Handle("/upload", fileUploadHandler)
	mux.Handle("/", fileServer)

	// Create server itself
	portStr := fmt.Sprintf(":%d", cfg.ServerPort)

	httpServer.srv = &http.Server{
		Addr:         portStr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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
