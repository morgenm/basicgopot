# BasicGoPot

**_A highly configurable and customizable honeypot server written in Go._**

[![Go](https://github.com/morgenm/basicgopot/actions/workflows/go.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/go.yml)
[![golangci](https://github.com/morgenm/basicgopot/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/golangci-lint.yml)
[![Gosec](https://github.com/morgenm/basicgopot/actions/workflows/gosec.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/gosec.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/morgenm/basicgopot)](https://goreportcard.com/report/github.com/morgenm/basicgopot)
[![Docs](https://pkg.go.dev/badge/github.com/morgenm/basicgopot)](https://pkg.go.dev/github.com/morgenm/basicgopot)
[![GitHub Downloads](https://img.shields.io/github/downloads/morgenm/basicgopot/total)](https://github.com/morgenm/basicgopot/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/morgenm/basicgopot)](https://hub.docker.com/r/morgenm/basicgopot/)
[![codecov](https://codecov.io/gh/morgenm/basicgopot/branch/main/graph/badge.svg?token=R2LE7BBNJQ)](https://codecov.io/gh/morgenm/basicgopot)

## About
Customizable HTTP honeypot which saves and logs all files uploaded to it. It can check file hashes against VirusTotal, upload files to VirusTotal, and save VirusTotal scan results. Configurable WebHooks let you easily customize what the server does once a file is uploaded. You can use any **HTML** and **CSS** to make the server look how you want it.

## Install

You can grab the latest release for this project from GitHub and just run the executable after [creating the config file](#configuration). Other options are listed below.

### Install with *go install*

```bash
go install github.com/morgenm/basicgopot/cmd/basicgopot@latest
```

### Docker-compose
To run with docker-compose, copy the compose file located in `build/docker-compose.yml`.

You can either set the location to the basicgopot files with:
```bash
export BASICGOPOT_LOC=/path/to/basicgopot
```
or edit the values in `build/docker-compose.yml`.

You will need to copy the example config to wherever you specify your `config` directory to be located and rename the file to `config.json`. By default, all logs will be saved to what you specify as the `logs` directory and uploads will be in `uploads`.

Run the following command to start the server:
```bash
docker compose up -d
```

### Docker image

Get the docker image by running:
```bash
docker pull morgenm/basicgopot:latest
```

To run the docker image:
```bash
docker run -p 8080:8080 -v $(pwd)/config:/config -v $(pwd)/uploads:/uploads:rw -v $(pwd)/logs:/logs morgenm/basicgopot:latest
```
The `echo` command must be run the first time the server is run because `uploads.json` must exist for it to not be mapped as a directory by docker.

### Building docker image

After downloading the source, run:
```bash
make docker
```
The docker image will be tagged as `basicgopot`.

### Building Locally

If you wish to build, you can: 
```bash
git clone https://github.com/morgenm/basicgopot
make
```
This will output the executable file `basicgopot` on Linux or Mac, and `basicgopot.exe` on Windows

## Configuration
The configuration for **_basicgopot_** is stored in `config/config.json`. An example config file is provided in `config/config.json.example`. You will need to rename `config/config.json.example` to `config/config.json` and fill in the configuration variables as you see fit. The configuration options are:
```json
{
    "ServerPort" : 8080, // The port the server runs on
    "LogFile" : "logs/log.log", // What file to save server logs to.
    "UploadLimitMB" : 512, // Size limit in Megabytes for a single file upload to the server
    "UseVirusTotal" : true, // Whether to use VirusTotal 
    "UploadVirusTotal" : true, // Whether to upload the sample to VirusTotal if it's unique
    "VirusTotalApiKey" : "lol", // VirusTotal user API key (needed if UseVirusTotal is true)
    "ScanOutputDir" : "logs/scans/", // Directory to store downloaded VirusTotal scans in 
    "UploadsDir" : "uploads/", // Directory to store files uploaded to the server
    "UploadLog" : "logs/uploads.json", // File for logging upload and scan/analysis information
    "WebHookDir" : "logs/webhooks/", // Directory to save WebHook responses
    "UploadWebHooks" : { // WebHook definitions. Set to {} for no WebHooks.
        "Flask" : { // Unique WebHook Name
            "URL" : "http://localhost:5000",
            "Method" : "POST", // Only POST is supported right now.
            "Headers" : { // Custom headers
                "api-key": "api-key",
                "user-agent": "basicgopot",
                "accept": "*/*"
            },
            "Forms" : { // Form field values
                "test" : "test field", // Any string is acceptable.
                "file" : "$FILE" // $FILE will be replaced with the file data and will turn this into a file field.
            }
        }  
    }
}
```

If `UploadVirusTotal` is false, but `UseVirusTotal` is true, the uploaded samples' hashes will be checked against VirusTotal, but they will not be uploaded. Note: `UseVirusTotal` has precedence over `UploadVirusTotal`, so if `UseVirusTotal` is false and `UploadVirusTotal` is true, `UploadVirusTotal` will be ignored. 
`ScanOutputDir`, `UploadsDir`, `UploadLog`, and `WebHookDir` can all be left empty (`""`) if you don't want to save scans, save the uploaded files, log them to the upload log file, or save WebHook responses, respectively.

UploadWebHooks are WebHooks that will execute every time a file is uploaded to the server. You can use this to send the file to other servers, such as sending the file to a **Cuckoo** server to queue it for analysis. Right now, only `POST` requests are supported. The `Forms` variable defines what data is sent to the given URL as a form, where the key is the field name and the value is the field value. These can be any strings, and any instance of `$FILE` in the string will be replaced with the entire data of the uploaded file. All WebHooks must have a unique name; the WebHook in this example is titled `Flask`. If you don't want to use any WebHooks, you can set `"UploadWebHooks" : {}`.


## VirusTotal
**_basicgopot_** can be configured to either check the hashes of uploaded files against **VirusTotal**, upload the files to **VirusTotal**, or both. The results of the scans can be saved to a chosen directory.

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
