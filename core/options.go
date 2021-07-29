package core

import (
	"flag"
)

type arrayFlags []string
type Options struct {
	OutDir            string
	SessionPath       string
	TemplatePath      string
	Proxy             string
	ChromePath        string
	Ports             string
	MatchCodes        string
	FilterCodes       string
	FilterString      string
	ThumbnailSize     string
	InputFile         string
	Threads           int
	Timeout           int
	ScanTimeout       int
	HTTPTimeout       int
	ScreenshotTimeout int
	ScreenshotDelay   int
	FollowRedirect    bool
	FullPage          bool
	Nmap              bool
	SaveBody          bool
	Silent            bool
	Version           bool
	Offline           bool
	Similarity	  float64
	HTTPHeaders       []string
}

func (a *arrayFlags) String() string {
    return ""
}

func (a *arrayFlags) Set(value string) error {
    *a = append(*a, value)
    return nil
}

func ParseOptions() (Options, error) {
	var headers arrayFlags

	opts := Options{}
	headers = []string{}

	flag.StringVar(&opts.ChromePath, "chrome-path", "", "Full path to the Chrome/Chromium executable to use. By default, aquatone will search for Chrome or Chromium")
	flag.StringVar(&opts.OutDir, "out", ".", "Directory to write files to")
	flag.StringVar(&opts.SessionPath, "session", "", "Load Aquatone session file and generate HTML report")
	flag.StringVar(&opts.TemplatePath, "template-path", "", "Path to HTML template to use for report")
	flag.StringVar(&opts.Proxy, "proxy", "", "Proxy to use for HTTP requests")
	flag.StringVar(&opts.MatchCodes, "match-codes", "", "Filter hosts that do not return any of these HTTP status codes (seperated by commas)")
	flag.StringVar(&opts.FilterCodes, "filter-codes", "", "Filter hosts that return any of these HTTP status codes (seperated by commas)")
	flag.StringVar(&opts.FilterString, "filter-string", "", "Filter host thats have this string in the response body")
	flag.StringVar(&opts.Ports, "ports", "80,443,8080,8443", "Ports to scan on hosts. Supported list aliases: small, medium, large, xlarge")
	flag.StringVar(&opts.ThumbnailSize, "thumbnail-size", "", "Screenshot thumbnail size (format: width,height)")
	flag.StringVar(&opts.InputFile, "input-file", "", "Input file to parse hosts (Nmap or Raw) rather than STDIN")
	flag.IntVar(&opts.Threads, "threads", 0, "Number of concurrent threads (default number of logical CPUs)")
	flag.IntVar(&opts.Timeout, "timeout", 0, "Generic timeout for everything. (specific timeouts will be ignored if set)")
	flag.IntVar(&opts.ScanTimeout, "scan-timeout", 3*1000, "Timeout in milliseconds for port scans")
	flag.IntVar(&opts.HTTPTimeout, "http-timeout", 15*1000, "Timeout in milliseconds for HTTP requests")
	flag.IntVar(&opts.ScreenshotTimeout, "screenshot-timeout", 40*1000, "Timeout in milliseconds for screenshots")
	flag.IntVar(&opts.ScreenshotDelay, "screenshot-delay", 0, "Delay in milliseconds before taking screenshots")
	flag.BoolVar(&opts.FullPage, "full-page", false, "Screenshot full web pages")
	flag.BoolVar(&opts.Nmap, "nmap", false, "Parse input as Nmap/Masscan XML")
	flag.BoolVar(&opts.FollowRedirect, "follow-redirect", false, "Follow HTTP redirects")
	flag.BoolVar(&opts.SaveBody, "save-body", true, "Save response bodies to files")
	flag.BoolVar(&opts.Silent, "silent", false, "Suppress all output except for errors")
	flag.BoolVar(&opts.Version, "version", false, "Print current Aquatone version")
	flag.BoolVar(&opts.Offline, "offline", false, "Use offline JS files to generate the template report (can be browsed without Internet)")
	flag.Float64Var(&opts.Similarity, "similarity", 0.85, "Similarity rate for screenshots clustering")
	flag.Var(&headers, "http-header", "Optional HTTP request header (can be used multiple times for multiple headers)")

	flag.Parse()

	opts.HTTPHeaders = headers
	if opts.Timeout != 0 {
		opts.ScanTimeout = opts.Timeout
		opts.HTTPTimeout = opts.Timeout
		opts.ScanTimeout = opts.Timeout
	}

	return opts, nil
}
