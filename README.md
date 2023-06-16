# BasicGoPot
[![Go](https://github.com/morgenm/basicgopot/actions/workflows/go.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/go.yml)
[![golangci](https://github.com/morgenm/basicgopot/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/golangci-lint.yml)
[![Gosec](https://github.com/morgenm/basicgopot/actions/workflows/gosec.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/gosec.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/morgenm/basicgopot)](https://goreportcard.com/report/github.com/morgenm/basicgopot)
[![GitHub Downloads](https://img.shields.io/github/downloads/morgenm/basicgopot/total)](https://github.com/morgenm/basicgopot/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/morgenm/basicgopot)](https://hub.docker.com/r/morgenm/basicgopot/)

**_A basic honeypot written in Go._**

![Basicgopot](https://raw.githubusercontent.com/morgenm/basicgopot/275d8f8fedc251dedce6a047a0cd8b023a94f2f8/docs/basicgopot.gif)

This honeypot is an HTTP server which will allow the user to upload any type of file. Uploaded files will be saved and scanned by VirusTotal, per the default configuration. To learn how to configure the server, see [Configuration](#configuration).

It serves HTML files that are put in the `web/static` directory. I included some rudimentary templates for the web server in `web/templates`. By default, `web/static` is a symbolic link to the `web/firmware_upload_v2` template. The program will create the `uploads` and `scans` directories. Any files uploaded to the server will be in the `uploads` directory, and VirusTotal results will be in the `scans` directory.

If the file already has been uploaded to VirusTotal, the honeypot will download the file data (scan results and other info) that is provided by VirusTotal. But, if it is unique, it will upload the file and just grab the analysis results. For the latter scenario, I would recommend opening up the analysis in a browser by grabbing the hash from the analysis scan result, or the log file, and putting it into VirusTotal manually.

## Configuration
The configuration for **_basicgopot_** is stored in `config/config.json`. An example config file is provided in `config/config.json.example`. You will need to rename `config/config.json.example` to `config/config.json` and fill in the configuration variables as you see fit. If you wish to use VirusTotal, you will need to put your API key in the config. The configuration options are:
```json
{
    "ServerPort" : 8080, // The port the server runs on
    "UploadLimitMB" : 512, // Size limit in Megabytes for a single file upload to the server
    "UseVirusTotal" : true, // Whether to use VirusTotal 
    "UploadVirusTotal" : true, // Whether to upload the sample to VirusTotal if its unique
    "VirusTotalApiKey" : "lol", // VirusTotal user API key (needed if UseVirusTotal is true)
    "ScanOutputDir" : "scans/", // Directory to store downloaded VirusTotal scans in 
    "UploadsDir" : "uploads/", // Directory to store files uploaded to the server
    "UploadLog" : "uploads.json" // File for logging upload and scan/analysis information
}
```

If `UploadVirusTotal` is false, but `UseVirusTotal` is true, the uploaded samples' hashes will be checked against VirusTotal, but they will not be uploaded. Note: `UseVirusTotal` has precedence over `UploadVirusTotal`, so if `UseVirusTotal` is false and `UploadVirusTotal` is true, `UploadVirusTotal` will be ignored. If `ScanOutputDir` is set to equal `""` (empty string), VirusTotal scan data will not be saved. Additionally, if `UploadLog` is `""`, no upload and scan/analysis information will be logged to a file, and `UploadsDir` can be empty to signify no saving of uploaded files.

## Running the tool

You can grab the latest release for this project from GitHub and just run the executable after creating the config file as described above. You can also get and run the Docker image, build the docker image locally, or build the project locally. All of these are described below.

### Docker image

Get the docker image by running:
```bash
docker pull morgenm/basicgopot:latest
```

To run the docker image:
```bash
echo "{}" > uploads.json
docker run --publish 8080:8080 -v $(pwd)/config:/config -v $(pwd)/uploads:/uploads-docker:rw -v $(pwd)/scans:/scans -v $(pwd)/uploads.json:/uploads.json basicgopot
```
The `touch` command must be run the first time the server is run because `uploads.json` must exist for it to not be mapped as a directory by docker.

### Building docker image

After downloading the source, run:
```bash
docker build -t basicgopot -f build/Dockerfile .
```
Where `basicgopot` can be any tag name.

### Building Locally
To run the honeypot, you can simply execute: `go run ./cmd/basicgopot`. 

If you wish to build, you can execute: `go build -o basicgopot.o ./cmd/basicgopot`, where `basicgopot.o` is whatever you wish to name the exectuable. If you do not specify the output name, the binary output will be named `basicgopot` (on Linux), which is not ignored by the .gitignore. This is something to keep in mind if you contribute.

## VirusTotal
Once a file is uploaded to the honeypot, it will be written to the "uploads" folder, checked against VirusTotal, and uploaded to VirusTotal if it is unique, as mentioned above. The log file will state that a file is uploaded, its hash will be listed, and some basic information about the VirusTotal upload will be outputted. 

![Sample log output](https://github.com/morgenm/basicgopot/blob/assets/docs/log.png?raw=true "Sample log output")

A sample JSON output is listed below. I uploaded Win32.Zeus to the server. This sample is already present on VirusTotal, so the scan results were saved.

![Win32.Zeus output](https://github.com/morgenm/basicgopot/blob/assets/docs/win32_zeus.png?raw=true "Win32.Zeus output")

## Templates
### Default template
The screenshot below displays the default template. It is a basic file upload form disguised as a firmware update upload. This template is named `firmware_update_v2`.

![Template Firmware Upload v2](https://github.com/morgenm/basicgopot/blob/assets/docs/template_firmware_upload_v2.png?raw=true "Default template")

### Resume upload
Another template provided is a simple job posting, where you write some basic info and upload a resume. This template is `resume_upload`.

![Template Resume](https://github.com/morgenm/basicgopot/blob/assets/docs/template_resume.png?raw=true "Resume template")

### Blog post upload
A more complete template is `blog_upload`. The "blog" is hosted at `/` and it has a "hidden" admin page for uploading posts at `/admin.html`. The admin file is listed as disallow in `robots.txt`. The blog posts are under `/posts/`. 

![Template Blog](https://github.com/morgenm/basicgopot/blob/assets/docs/template_blog_index.png?raw=true "Blog template")

![Template Blog Post](https://github.com/morgenm/basicgopot/blob/assets/docs/template_blog_post.png?raw=true "Blog post")

![Template Blog Upload](https://github.com/morgenm/basicgopot/blob/assets/docs/template_blog_upload.png?raw=true "Blog admin upload")
