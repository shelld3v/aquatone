package agents

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/shelld3v/aquatone/core"
)

type URLTlsChecker struct {
	session      *core.Session
}

func NewURLTlsChecker() *URLTlsChecker {
	return &URLTlsChecker{}
}

func (a *URLTlsChecker) ID() string {
	return "agent:url_tls_checker"
}

func (a *URLTlsChecker) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	a.session = s

	return nil
}

func (a *URLTlsChecker) OnURLResponsive(url string) {
	var conn *tls.Conn
	var err  error

	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	versions := map[uint16]string{
		tls.VersionSSL30: "SSLv3",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
	}

	a.session.Out.Debug("[%s] Received new responsive URL: %s\n", a.ID(), url)
	page := a.session.GetPage(url)
	if page == nil {
		a.session.Out.Error("Unable to find page for URL: %s\n", url)
		return
	}

	a.session.WaitGroup.Add()
	go func(page *core.Page) {
		defer a.session.WaitGroup.Done()

		if !strings.HasPrefix(page.URL, "https://") {
			return
		}

		client := &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					conn, err = tls.Dial(network, addr, tlsConfig)
					return conn, err
				},
			},
		}
		_, err = client.Get(page.URL)

		if err != nil {
			a.session.Out.Debug("[%s] Unable to identify TLS information for %s: %s\n", a.ID(), page.URL, err)
			return
		}

		version := versions[conn.ConnectionState().Version]
		a.session.Out.Debug("[%s] %s uses %s\n", a.ID(), page.URL, version)
		if version != "TLS 1.2" {
			page.AddTag(fmt.Sprintf("Insecure %s", version), "dark", "https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/")
		}
	}(page)
}
