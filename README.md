# BasicGoPot
[![Go](https://github.com/morgenm/basicgopot/actions/workflows/go.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/go.yml)
[![golangci](https://github.com/morgenm/basicgopot/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/golangci-lint.yml)
[![Gosec](https://github.com/morgenm/basicgopot/actions/workflows/gosec.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/gosec.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/morgenm/basicgopot)](https://goreportcard.com/report/github.com/morgenm/basicgopot)

**_A basic honeypot written in Go._**

![Basicgopot](docs/basgicgopot.gif)

This honeypot is an HTTP server which will allow the user to upload any type of file. The files are written to the uploads directory and then are, by default, passed to VirusTotal to see if they are malicious. The VirusTotal results are written to the scans directory. The server is configurable, see [Configuration](#configuration).

It serves HTML files that are put in the `static` directory. I included a very rudimentary template, which `static` is a symbolic link to. To run this code, rename `config.json.example` to `config.json `and fill in the configuration variables as you see fit. Then run `go run .`

If you wish to use VirusTotal, you will need to put your API key in the config. Any files uploaded to the server will be in the `uploads` directory, and VirusTotal results will be in the `scans` directory.

As of right now, if the file already has been uploaded to VirusTotal, the honeypot will download the entire file data that is provided by VirusTotal. But, if it is unique, it will upload the file and just grab the analysis results (after waiting a short time). For the latter scenario, I would recommend opening up the analysis in a browser by grabbing the hash from the analysis scan result and putting it into VirusTotal manually.

## Configuration
The configuration for *basicgopot* is stored in `config.json`. An example config file is provided in `config.json.example`. The configuration options are:
```json
{
    "ServerPort" : 8080, // The port the server runs on
    "UploadLimitMB" : 512, // Size limit in Megabytes for a single file upload to the server
    "UseVirusTotal" : true, // Whether to use VirusTotal 
    "UploadVirusTotal" : true, // Whether to upload the sample to VirusTotal if its unique
    "VirusTotalApiKey" : "lol" // VirusTotal user API key (needed if UseVirusTotal is true)
}
```

If `UploadVirusTotal` is false, but `UseVirusTotal` is true, the uploaded samples' hashes will be checked against VirusTotal, but they will not be uploaded. If `UseVirusTotal` is false and `UploadVirusTotal` is true, `UploadVirusTotal` will be ignored, and the samples will just be saved to disk.

## VirusTotal
Once a file is uploaded to the honeypot, it will be written to the "uploads" folder, checked against VirusTotal, and uploaded to VirusTotal if it is unique, as mentioned above. The log file will state that a file is uploaded, its hash will be listed, and some basic information about the VirusTotal upload will be outputted. 

![Sample log output](docs/log.png?raw=true "Sample log output")

A sample JSON output is listed below. I uploaded Win32.Zeus to the server. This sample is already present on VirusTotal, so the scan results were saved.

![Win32.Zeus output](docs/win32_zeus.png?raw=true "Win32.Zeus output")

## Templates
### Default template
The screenshot below displays the default template. It is a basic file upload form disguised as a firmware update upload. This template is named `firmware_update_v2`.

![Template Firmware Upload v2](docs/template_firmware_upload_v2.png?raw=true "Default template")

### Resume upload
Another template provided is a simple job posting, where you write some basic info and upload a resume. This template is `resume_upload`.

![Template Resume](docs/template_resume.png?raw=true "Resume template")

### Blog post upload
A more complete template is `blog_upload`. The "blog" is hosted at `/` and it has a "hidden" admin page for uploading posts at `/admin.html`. The admin file is listed as disallow in `robots.txt`. The blog posts are under `/posts/`. 

![Template Blog](docs/template_blog_index.png?raw=true "Blog template")

![Template Blog Post](docs/template_blog_post.png?raw=true "Blog post")

![Template Blog Upload](docs/template_blog_upload.png?raw=true "Blog admin upload")
