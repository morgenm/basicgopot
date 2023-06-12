# BasicGoPot
A basic honeypot in Go which I wrote most of in a day.

The honeypot is an HTTP server which will allow the user to upload any type of file. The files are written to the uploads directory and then are passed to VirusTotal to see if they are malicious. The VirusTotal results are written to the scans directory.

It serves HTML files that are put in the `static` directory. I included a very rudimentary template, which static is a symbolic link to. To run this code, rename config.json.example to config.json and fill in the configuration variables as you see fit. Then run `go run .`

For using VirusTotal you will need to put your API key in the config. Any files uploaded to the server will be in the `uploads` directory, and VirusTotal results are in the `scans` directory.

As of right now, if the file already has been uploaded to VirusTotal, the honeypot will download the entire file data. But, if it is unique, it will upload the file and grab the analysis results (after waiting a short time). For the latter, I would recommend opening up the analysis in a browser by grabbing the hash from the analysis scan result and putting it into VirusTotal manually.

I put a workflow in place using the [Horusec](https://horusec.io/site/) SAST engine to check for vulnerabilities in the code.

## Default template
The screenshot below displays the default template, firmware_update_v2. It is a basic file upload form disguised as a firmware update upload.

![Template Firmware Upload v2](docs/template_firmware_upload_v2.png?raw=true "Default template")

## VirusTotal
Once the file is uploaded, it will be written to the "uploads" folder and then checked against VirusTotal, and uploaded if it is unique, as mentioned above. The log file will state that a file is uploaded, its hash will be listed, and some basic information about the VirusTotal upload will be outputted. 

![Sample log output](docs/log.png?raw=true "Sample log output")

A sample JSON output is listed below. I uploaded Win32.Zeus to the server. This sample is already present on VirusTotal, so the scan results were saved.

![Win32.Zeus output](docs/win32_zeus.png?raw=true "Win32.Zeus output")