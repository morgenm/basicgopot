// The webhook package contains code for defining and executing custom WebHook.
package webhook

// WebHook is a request that is made by the server once an event occurs. Currently, the only type
// of WebHook are those that are run once a file is uploaded to a server.
type WebHook struct {
	URL     string // URL that the request will be made to.
	Method  string // HTTP method for the request.
	Headers string // HTTP headers for the request.
	Data    []byte // Data to be sent in the request if it has method POST.
}

func (w WebHook) Execute() {
}
