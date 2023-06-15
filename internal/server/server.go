package server

import (
	"fmt"
	"log"
	
	"net/http"
	
	"time"

	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/errors"
)

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
