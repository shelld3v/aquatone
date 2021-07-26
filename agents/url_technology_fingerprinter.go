package agents

import (
	"fmt"

	"github.com/shelld3v/aquatone/core"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type URLTechnologyFingerprinter struct {
	session      *core.Session
}

func NewURLTechnologyFingerprinter() *URLTechnologyFingerprinter {
	return &URLTechnologyFingerprinter{}
}

func (a *URLTechnologyFingerprinter) ID() string {
	return "agent:url_technology_fingerprinter"
}

func (a *URLTechnologyFingerprinter) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	a.session = s

	return nil
}

func (a *URLTechnologyFingerprinter) OnURLResponsive(url string) {
	a.session.Out.Debug("[%s] Received new responsive URL %s\n", a.ID(), url)
	page := a.session.GetPage(url)
	if page == nil {
		a.session.Out.Error("Unable to find page for URL: %s\n", url)
		return
	}

	a.session.WaitGroup.Add()
	go func(page *core.Page) {
		defer a.session.WaitGroup.Done()

		body, err := a.session.ReadFile(fmt.Sprintf("html/%s.html", page.BaseFilename()))
		if err != nil {
			a.session.Out.Debug("[%s] Error reading HTML body file for %s: %s\n", a.ID(), page.URL, err)
			return
		}
		headers := map[string][]string{}
		for _, header := range page.Headers {
			headers[header.Name] = []string{header.Value}
		}

		wappalyzerClient, err := wappalyzer.New()
		if err != nil {
			a.session.Out.Debug("[%s] Unable to create wappalyzer client (wappalyzergo)\n", a.ID())
			return
		}

		fingerprints := wappalyzerClient.Fingerprint(headers, body)
		for service := range fingerprints {
			page.AddTag(service, "info", "about:blank") // wappalyzergo fingerprints doesn't contain website information
		}
	}(page)
}
