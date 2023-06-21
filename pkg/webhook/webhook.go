// The webhook package contains code for defining and executing custom WebHook.
package webhook

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/errors"
)

// WebHookField is a field for a form request.
type WebHookField struct {
	isFile bool   // Is the current field a file to be uploaded.
	data   []byte // The actual data for the form field.
}

// WebHook is a request that is made by the server once an event occurs. Currently, the only type
// of WebHook are those that are run once a file is uploaded to a server.
type WebHook struct {
	URL        string                  // URL that the request will be made to.
	Method     string                  // HTTP method for the request.
	Headers    map[string]string       // HTTP headers for the request.
	FormsBytes map[string]WebHookField // Actual data of the forms to be sent in the request.
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
	formBytes := make(map[string]WebHookField)
	for formName, formData := range c.Forms {
		data := []byte(formData)
		field := WebHookField{}
		isReplaced := false
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
					isReplaced = true
					if webHookString == "$FILE" {
						field.isFile = true
					}

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
		if isReplaced {
			field.data = data
		} else {
			field.data = []byte(formData)
		}

		formBytes[formName] = field
	}

	w.FormsBytes = formBytes
	return &w
}

// makePostRequest will use the data defined in the WebHook to make a POST request. Returns (*io.ReadCloser, nil)
// on success, (nil, error) on failure. The *io.ReadCloser is the reader for the response retrieved by the request.
func (w *WebHook) makePostRequest() (*io.ReadCloser, error) {
	// Create form for the POST request
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)

	for formName, field := range w.FormsBytes {
		if field.isFile {
			reader := bytes.NewReader(field.data) // Create bytes reader for data
			form, err := writer.CreateFormFile(formName, "filename")
			if err != nil {
				return nil, err
			}

			if _, err = io.Copy(form, reader); err != nil {
				return nil, err
			}
		} else {
			if err := writer.WriteField(formName, string(field.data)); err != nil {
				return nil, err
			}
		}
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	// Make POST request
	client := &http.Client{}
	req, err := http.NewRequest("POST", w.URL, buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	for headerName, headerVal := range w.Headers {
		req.Header.Add(headerName, headerVal)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 || resp.StatusCode < 200 {
		respBody := []byte{}
		if _, err := resp.Body.Read(respBody); err == nil {
			return nil, fmt.Errorf("%w with response code %d and response: %s", &errors.WebHookBadResponse{}, resp.StatusCode, string(respBody))
		} else {
			return nil, &errors.WebHookBadResponse{}
		}
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
