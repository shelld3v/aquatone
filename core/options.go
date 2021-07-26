package core

import (
	"flag"
)

type Options struct {
	Threads           *int
	Timeout           *int
	OutDir            *string
	SessionPath       *string
	TemplatePath      *string
	Proxy             *string
	ChromePath        *string
	Ports             *string
	MatchCodes        *string
	FilterCodes       *string
	ScanTimeout       *int
	HTTPTimeout       *int
	ScreenshotTimeout *int
	ScreenshotDelay   *int
        ThumbnailSize     *string
        FullPage          *bool
	Nmap              *bool
	NoRedirect        *bool
	SaveBody          *bool
	Silent            *bool
	Debug             *bool
	Version           *bool
	Offline           *bool
	Similarity	  *float64
	InputFile	  *string
}

func ParseOptions() (Options, error) {
	options := Options{
		Threads:           flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		Timeout:           flag.Int("timeout", 0, "Generic timeout for everything. (specific timeouts will be ignored if set)"),
		OutDir:            flag.String("out", ".", "Directory to write files to"),
		SessionPath:       flag.String("session", "", "Load Aquatone session file and generate HTML report"),
		TemplatePath:      flag.String("template-path", "", "Path to HTML template to use for report"),
		Proxy:             flag.String("proxy", "", "Proxy to use for HTTP requests"),
		MatchCodes:        flag.String("match-codes", "", "Valid HTTP status codes to do screenshot (seperated by commas)"),
		FilterCodes:       flag.String("filter-codes", "", "Invalid HTTP status codes to do screenshot (seperated by commas)"),
		ChromePath:        flag.String("chrome-path", "", "Full path to the Chrome/Chromium executable to use. By default, aquatone will search for Chrome or Chromium"),
		Ports:             flag.String("ports", "80,443,8080,8443", "Ports to scan on hosts. Supported list aliases: small, medium, large, xlarge"),
		ScanTimeout:       flag.Int("scan-timeout", 3*1000, "Timeout in miliseconds for port scans"),
		HTTPTimeout:       flag.Int("http-timeout", 15*1000, "Timeout in miliseconds for HTTP requests"),
		ScreenshotTimeout: flag.Int("screenshot-timeout", 30*1000, "Timeout in miliseconds for screenshots"),
		ScreenshotDelay:   flag.Int("screenshot-delay", 0, "Delay in miliseconds before taking screenshots"),
                ThumbnailSize:     flag.String("thumbnail-size", "", "Screenshot thumbnail size (format: width,height)"),
		FullPage:          flag.Bool("full-page", false, "Screenshot full web pages"),
		Nmap:              flag.Bool("nmap", false, "Parse input as Nmap/Masscan XML"),
		NoRedirect:        flag.Bool("no-redirect", false, "Do not follow HTTP redirects"),
		SaveBody:          flag.Bool("save-body", true, "Save response bodies to files"),
		Similarity:	   flag.Float64("similarity", 0.80, "Similarity rate for screenshots clustering"),
		Silent:            flag.Bool("silent", false, "Suppress all output except for errors"),
		Debug:             flag.Bool("debug", false, "Print debugging information"),
		Version:           flag.Bool("version", false, "Print current Aquatone version"),
		Offline:           flag.Bool("offline", false, "Use offline JS files to generate the template report (can be browsed without Internet)"),
		InputFile:	   flag.String("input-file", "", "Input file to parse hosts (Nmap or Raw) rather than STDIN"),
	}

	flag.Parse()

	if *options.Timeout != 0 {
		*options.ScanTimeout = *options.Timeout
		*options.HTTPTimeout = *options.Timeout
		*options.ScanTimeout = *options.Timeout
	}

	return options, nil
}
