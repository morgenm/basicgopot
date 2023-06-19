// The webhook package contains code for defining and executing custom WebHook.
package webhook

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/errors"
)

// WebHook is a request that is made by the server once an event occurs. Currently, the only type
// of WebHook are those that are run once a file is uploaded to a server.
type WebHook struct {
	URL       string // URL that the request will be made to.
	Method    string // HTTP method for the request.
	Headers   string // HTTP headers for the request.
	DataBytes []byte // Actual data to be sent in the request
}

// NewWebHook creates a WebHook from a WebHookConfig. In doing so, it will evaluate any WebHook strings like $FILE.
// It takes a WebHookConfig and a map of strings to bytes. The map of strings to bytes are the WebHook strings
// mapped to the data that they will be replaced by. Returns a pointer to a new WebHook.
func NewWebHook(c config.WebHookConfig, webHookStringMap map[string][]byte) *WebHook {
	// Copy over from config.
	w := WebHook{
		URL:     c.URL,
		Method:  c.Method,
		Headers: c.Headers,
	}

	// Split on each WebHook string so we can add in the real data.
	data := []byte(c.Data)
	for webHookString, replacementData := range webHookStringMap {
		i := 0
		for {
			if i >= len(data) {
				break
			}

			isMatch := true
			for j := i; j < i+len(webHookString); j++ {
				if data[j] != webHookString[j-i] {
					isMatch = false
					break
				}
			}
			if isMatch {
				oldData := make([]byte, len(data))
				copy(oldData, data)
				data = append(oldData[:i], replacementData...)
				if i+len(webHookString) < len(oldData) {
					data = append(data, oldData[i+len(webHookString):]...)
				} else {
					break
				}
				i += len(replacementData)
			} else {
				i++
			}
		}
	}

	w.DataBytes = data
	return &w
}

// makePostRequest will use the data defined in the WebHook to make a POST request. Returns (*io.ReadCloser, nil)
// on success, (nil, error) on failure. The *io.ReadCloser is the reader for the response retrieved by the request.
func (w *WebHook) makePostRequest() (*io.ReadCloser, error) {
	// Create form file for upload
	buf := new(bytes.Buffer)
	reader := bytes.NewReader(w.DataBytes) // Create bytes reader for data
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("file", "file")
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
	req, err := http.NewRequest("POST", w.URL, buf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("boundary", writer.Boundary())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, &errors.WebHookBadResponse{}
	}

	return &resp.Body, nil
}

// Execute will make the request defined by the WebHook. Returns (*io.ReadCloser, nil) on success, (nil, error) on failure.
// The *io.ReadCloser is the reader for the response retrieved by the request.
func (w *WebHook) Execute() (*io.ReadCloser, error) {
	switch w.Method {
	case "POST":
		return w.makePostRequest()
	default:
		return nil, &errors.WebHookInvalidMethod{}
	}
}
