# BasicGoPot
A basic honeypot in Go which I wrote most of in a day.

The honeypot is an HTTP server which will allow the user to upload any type of file. The files are written to the uploads directory and then are passed to VirusTotal to see if they are malicious. The VirusTotal results are written to the scans directory.

It serves HTML files that are put in the `static` directory. I included a very rudimentary template, which static is a symbolic link to. To run this code, rename config.json.example to config.json and fill in the configuration variables as you see fit. Then run `go run .`

For using VirusTotal you will need to put your API key in the config. Any files uploaded to the server will be in the `uploads` directory, and VirusTotal results are in the `scans` directory.

As of right now, if the file already has been uploaded to VirusTotal, the honeypot will download the entire file data. But, if it is unique, it will upload the file and grab the analysis results (after waiting a short time). For the latter, I would recommend opening up the analysis in a browser by grabbing the hash from the analysis scan result and putting it into VirusTotal manually.