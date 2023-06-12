# BasicGoPot
[![Go](https://github.com/morgenm/basicgopot/actions/workflows/go.yml/badge.svg)](https://github.com/morgenm/basicgopot/actions/workflows/go.yml)

A basic honeypot in Go which I wrote most of in a day.

The honeypot is an HTTP server which will allow the user to upload any type of file. The files are written to the uploads directory and then are passed to VirusTotal to see if they are malicious. The VirusTotal results are written to the scans directory.

It serves HTML files that are put in the `static` directory. I included a very rudimentary template, which static is a symbolic link to. To run this code, rename config.json.example to config.json and fill in the configuration variables as you see fit. Then run `go run .`

For using VirusTotal you will need to put your API key in the config. Any files uploaded to the server will be in the `uploads` directory, and VirusTotal results are in the `scans` directory.

As of right now, if the file already has been uploaded to VirusTotal, the honeypot will download the entire file data. But, if it is unique, it will upload the file and grab the analysis results (after waiting a short time). For the latter, I would recommend opening up the analysis in a browser by grabbing the hash from the analysis scan result and putting it into VirusTotal manually.

I put a workflow in place using the [Horusec](https://horusec.io/site/) SAST engine to check for vulnerabilities in the code.

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


## VirusTotal
Once the file is uploaded, it will be written to the "uploads" folder and then checked against VirusTotal, and uploaded if it is unique, as mentioned above. The log file will state that a file is uploaded, its hash will be listed, and some basic information about the VirusTotal upload will be outputted. 

![Sample log output](docs/log.png?raw=true "Sample log output")

A sample JSON output is listed below. I uploaded Win32.Zeus to the server. This sample is already present on VirusTotal, so the scan results were saved.

![Win32.Zeus output](docs/win32_zeus.png?raw=true "Win32.Zeus output")
