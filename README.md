# BasicGoPot
A basic honeypot I wrote in Go in a day. 

It serves HTML files that are put in the `static` directory. I included a very rudimentary template, which static is a symbolic link to. To run this code, rename config.json.example to config.json and fill in the configuration variables as you see fit. For using VirusTotal you will need to put your API key in the config. Any files uploaded to the server will be in the `uploads` directory, and VirusTotal results are in the `scans` directory.