package agents

import (
	"fmt"
	"net"
	"strings"

	"github.com/shelld3v/aquatone/core"
)

type URLTakeoverDetector struct {
	session *core.Session
}

func NewURLTakeoverDetector() *URLTakeoverDetector {
	return &URLTakeoverDetector{}
}

func (d *URLTakeoverDetector) ID() string {
	return "agent:url_takeover_detector"
}

func (a *URLTakeoverDetector) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	a.session = s
	return nil
}

func (a *URLTakeoverDetector) OnURLResponsive(u string) {
	a.session.Out.Debug("[%s] Received new url: %s\n", a.ID(), u)
	page := a.session.GetPage(u)
	if page == nil {
		a.session.Out.Error("Unable to find page for URL: %s\n", u)
		return
	}

	if page.IsIPHost() {
		a.session.Out.Debug("[%s] Skipping takeover detection on IP URL %s\n", a.ID(), u)
		return
	}

	a.session.WaitGroup.Add()
	go func(p *core.Page) {
		defer a.session.WaitGroup.Done()
		a.runDetectorFunctions(p)
	}(page)
}

func (a *URLTakeoverDetector) runDetectorFunctions(page *core.Page) {
	hostname := page.ParsedURL().Hostname()
	addrs, err := net.LookupHost(fmt.Sprintf("%s.", hostname))
	if err != nil {
		a.session.Out.Error("Unable to resolve %s to IP addresses: %s\n", hostname, err)
		return
	}
	cname, err := net.LookupCNAME(fmt.Sprintf("%s.", hostname))
	if err != nil {
		a.session.Out.Error("Unable to resolve %s to CNAME: %s\n", hostname, err)
		return
	}

	a.session.Out.Debug("[%s] IP addresses for %s: %v\n", a.ID(), hostname, addrs)
	a.session.Out.Debug("[%s] CNAME for %s: %s\n", a.ID(), hostname, cname)

	body, err := a.session.ReadFile(fmt.Sprintf("html/%s.html", page.BaseFilename()))
	if err != nil {
		a.session.Out.Debug("[%s] Error reading HTML body file for %s: %s\n", a.ID(), page.URL, err)
		return
	}

	if a.detectGithubPages(page, addrs, cname, string(body)) {
		return
	}

	if a.detectAmazonS3(page, addrs, cname, string(body)) {
		return
	}

	if a.detectCargoCollective(page, addrs, cname, string(body)) {
		return
	}

	if a.detectGhost(page, addrs, cname, string(body)) {
		return
	}

	if a.detectHelpjuice(page, addrs, cname, string(body)) {
		return
	}

	if a.detectHelpScout(page, addrs, cname, string(body)) {
		return
	}

	if a.detectHeroku(page, addrs, cname, string(body)) {
		return
	}

	if a.detectJetBrains(page, addrs, cname, string(body)) {
		return
	}

	if a.detectMicrosoftAzure(page, addrs, cname, string(body)) {
		return
	}

	if a.detectReadme(page, addrs, cname, string(body)) {
		return
	}

	if a.detectSurge(page, addrs, cname, string(body)) {
		return
	}

	if a.detectTumblr(page, addrs, cname, string(body)) {
		return
	}

	if a.detectUserVoice(page, addrs, cname, string(body)) {
		return
	}

	if a.detectWordpress(page, addrs, cname, string(body)) {
		return
	}

	if a.detectSmugMug(page, addrs, cname, string(body)) {
		return
	}

	if a.detectStrikingly(page, addrs, cname, string(body)) {
		return
	}

	if a.detectUptimeRobot(page, addrs, cname, string(body)) {
		return
	}

	if a.detectPantheon(page, addrs, cname, string(body)) {
		return
	}

	if a.detectAgile(page, addrs, cname, string(body)) {
		return
	}

	if a.detectKinsta(page, addrs, cname, string(body)) {
		return
	}

	if a.detectCampaignMonitor(page, addrs, cname, string(body)) {
		return
	}

	if a.detectGemfury(page, addrs, cname, string(body)) {
		return
	}

	if a.detectLaunchRock(page, addrs, cname, string(body)) {
		return
	}

	if a.detectBigCartel(page, addrs, cname, string(body)) {
                return
        }

	if a.detectTeamWork(page, addrs, cname, string(body)) {
		return
	}

	if a.detectShopify(page, addrs, cname, string(body)) {
		return
	}

	if a.detectBitbucket(page, addrs, cname, string(body)) {
		return
	}

	if a.detectIntercom(page, addrs, cname, string(body)) {
		return
	}
}

func (a *URLTakeoverDetector) detectGithubPages(p *core.Page, addrs []string, cname string, body string) bool {
	githubAddrs := [...]string{"185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"}
	fingerprints := [...]string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"}
	for _, githubAddr := range githubAddrs {
		for _, addr := range addrs {
			if addr == githubAddr {
				for _, fingerprint := range fingerprints {
					if strings.Contains(body, fingerprint) {
						p.AddTag("Github Page domain takeover", "dark", "https://help.github.com/articles/using-a-custom-domain-with-github-pages/")
						a.session.Out.Warn("%s: vulnerable to takeover on Github Pages\n", p.URL)
						return true
					}
				}
				return true
			}
		}
	}
	return false
}

func (a *URLTakeoverDetector) detectAmazonS3(p *core.Page, addrs []string, cname string, body string) bool {
	fingerprints := [...]string{"NoSuchBucket", "The specified bucket does not exist"}
	if !strings.HasSuffix(cname, ".amazonaws.com.") {
		return false
	}
	for _, fingerprint := range fingerprints {
		if strings.Contains(body, fingerprint) {
			p.AddTag("Amazon S3 domain takeover", "dark", "https://docs.aws.amazon.com/AmazonS3/latest/dev/website-hosting-custom-domain-walkthrough.html")
			a.session.Out.Warn("%s: vulnerable to takeover on Amazon S3\n", p.URL)
			return true
		}
	}
	return true
}

func (a *URLTakeoverDetector) detectCampaignMonitor(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".createsend.com.") {
		return false
	}
	if strings.Contains(body, "Double check the URL or ") {
		p.AddTag("Campaign Monitor domain takeover", "dark", "https://help.campaignmonitor.com/custom-domain-names")
		a.session.Out.Warn("%s: vulnerable to takeover on Campaign Monitor\n", p.URL)
		return true
	}
	return true
}

func (a *URLTakeoverDetector) detectCargoCollective(p *core.Page, addrs []string, cname string, body string) bool {
	if cname != "subdomain.cargocollective.com." {
		return false
	}
	if strings.Contains(body, "404 Not Found") {
		p.AddTag("CargoCollective domain takeover", "dark", "https://support.2.cargocollective.com/Using-a-Third-Party-Domain")
		a.session.Out.Warn("%s: vulnerable to takeover on Cargo Collective\n", p.URL)
		return true
	}
	return true
}

func (a *URLTakeoverDetector) detectGhost(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".ghost.io.") {
		return false
	}
	if strings.Contains(body, "The thing you were looking for is no longer here, or never was") {
		p.AddTag("Ghost domain takeover", "dark", "https://docs.ghost.org/faq/using-custom-domains/")
		a.session.Out.Warn("%s: vulnerable to takeover on Ghost\n", p.URL)
		return true
	}
	return true
}

func (a *URLTakeoverDetector) detectHelpjuice(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".helpjuice.com.") {
		return false
	}
	if strings.Contains(body, "We could not find what you're looking for.") {
		p.AddTag("Help Juice domain takeover", "dark", "https://help.helpjuice.com/34339-getting-started/custom-domain")
		a.session.Out.Warn("%s: vulnerable to takeover on Helpjuice\n", p.URL)
		return true
	}
	return false
}

func (a *URLTakeoverDetector) detectHelpScout(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".helpscoutdocs.com.") {
		return false
	}
	if strings.Contains(body, "No settings were found for this company:") {
		p.AddTag("Help Scout domain takeover", "dark", "https://docs.helpscout.net/article/42-setup-custom-domain")
		a.session.Out.Warn("%s: vulnerable to takeover on HelpScout\n", p.URL)
		return true
	}
	return true
}

func (a *URLTakeoverDetector) detectHeroku(p *core.Page, addrs []string, cname string, body string) bool {
	herokuCnames := [...]string{".herokudns.com.", ".herokuapp.com.", ".herokussl.com."}
	for _, herokuCname := range herokuCnames {
		if strings.HasSuffix(cname, herokuCname) {
			if strings.Contains(body, "No such app") {
				p.AddTag("Heroku domain takeover", "dark", "https://devcenter.heroku.com/articles/custom-domains")
				a.session.Out.Warn("%s: vulnerable to takeover on Heroku\n", p.URL)
				return true
			}
			return true
		}
	}
	return false
}

func (a *URLTakeoverDetector) detectJetBrains(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".myjetbrains.com.") {
		return false
	}
	if strings.Contains(body, "is not a registered InCloud YouTrack") {
		p.AddTag("JetBrains domain takeover", "dark", "https://www.jetbrains.com/help/youtrack/incloud/Domain-Settings.html#use-custom-domain-name")
		a.session.Out.Warn("%s: vulnerable to takeover on JetBrains\n", p.URL)
		return true
	}
	return true
}

func (a *URLTakeoverDetector) detectMicrosoftAzure(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".azurewebsites.net.") {
		return false
	}
	if strings.Contains(body, "404 Web Site not found") {
		p.AddTag("Azure domain takeover", "dark", "https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain")
		a.session.Out.Warn("%s: vulnerable to takeover on Microsoft Azure\n", p.URL)
		return true
	}
	return true
}

func (a *URLTakeoverDetector) detectReadme(p *core.Page, addrs []string, cname string, body string) bool {
	readmeCnames := [...]string{".readme.io.", ".readmessl.com."}
	for _, readmeCname := range readmeCnames {
		if strings.HasSuffix(cname, readmeCname) {
			if strings.Contains(body, "Project doesnt exist... yet!") {
				p.AddTag("Readme domain takeover", "dark", "https://readme.readme.io/docs/setting-up-custom-domain")
				a.session.Out.Warn("%s: vulnerable to takeover on Readme\n", p.URL)
				return true
			}
			return true
		}
	}
	return false
}

func (a *URLTakeoverDetector) detectSurge(p *core.Page, addrs []string, cname string, body string) bool {
	detected := false
	for _, addr := range addrs {
		if addr == "45.55.110.124" {
			detected = true
			break
		}
	}
	if cname == "na-west1.surge.sh." {
		detected = true
	}
	if detected {
		if strings.Contains(body, "project not found") {
			p.AddTag("Surge domain takeover", "dark", "https://surge.sh/help/adding-a-custom-domain")
			a.session.Out.Warn("%s: vulnerable to takeover on Surge\n", p.URL)
		}
		return true
	}
	return false
}

func (a *URLTakeoverDetector) detectTumblr(p *core.Page, addrs []string, cname string, body string) bool {
	detected := false
	for _, addr := range addrs {
		if addr == "66.6.44.4" {
			detected = true
			break
		}
	}
	if cname == "domains.tumblr.com." {
		detected = true
	}
	if detected {
		if strings.Contains(body, "Whatever you were looking for doesn't currently exist at this address") {
			p.AddTag("Tumblr domain takeover", "dark", "https://tumblr.zendesk.com/hc/en-us/articles/231256548-Custom-domains")
			a.session.Out.Warn("%s: vulnerable to takeover on Tumblr\n", p.URL)
		}
		return true
	}
	return false
}

func (a *URLTakeoverDetector) detectUserVoice(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".uservoice.com.") {
		return false
	}
	if strings.Contains(body, "This UserVoice subdomain is currently available!") {
		p.AddTag("UserVoice domain takeover", "dark", "https://developer.uservoice.com/docs/site/domain-aliasing/")
		a.session.Out.Warn("%s: vulnerable to takeover on UserVoice\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectWordpress(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".wordpress.com.") {
		return false
	}
	if strings.Contains(body, "Do you want to register") {
		p.AddTag("Wordpress domain takeover", "dark", "https://en.support.wordpress.com/domains/map-subdomain/")
		a.session.Out.Warn("%s: vulnerable to takeover on Wordpress\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectSmugMug(p *core.Page, addrs []string, cname string, body string) bool {
	if cname != "domains.smugmug.com." {
		return false
	}
	if body == "" {
		p.AddTag("SmugMug domain takeover", "dark", "https://help.smugmug.com/use-a-custom-domain-BymMexwJVHG")
		a.session.Out.Warn("%s: vulnerable to takeover on SmugMug\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectStrikingly(p *core.Page, addrs []string, cname string, body string) bool {
	detected := false
	for _, addr := range addrs {
		if addr == "54.183.102.22" {
			detected = true
			break
		}
	}
	if strings.HasSuffix(cname, ".s.strikinglydns.com.") {
		detected = true
	}
	if detected {
		if strings.Contains(body, "But if you're looking to build your own website,") {
			p.AddTag("Strikingly domain takeover", "dark", "https://support.strikingly.com/hc/en-us/articles/215046947-Connect-Custom-Domain")
			a.session.Out.Warn("%s: vulnerable to takeover on Strikingly\n", p.URL)
		}
		return true
	}
	return false
}

func (a *URLTakeoverDetector) detectUptimeRobot(p *core.Page, addrs []string, cname string, body string) bool {
	if cname != "stats.uptimerobot.com." {
		return false
	}
	if strings.Contains(body, "This public status page <b>does not seem to exist</b>.") {
		p.AddTag("Uptime Robot domain takeover", "dark", "https://blog.uptimerobot.com/introducing-public-status-pages-yay/")
		a.session.Out.Warn("%s: vulnerable to takeover on UptimeRobot\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectPantheon(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".pantheonsite.io.") {
		return false
	}
	if strings.Contains(body, "The gods are wise") {
		p.AddTag("Pantheon domain takeover", "dark", "https://pantheon.io/docs/domains/")
		a.session.Out.Warn("%s: vulnerable to takeover on Pantheon\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectAgile(p *core.Page, addrs []string, cname string, body string) bool {
	if cname != "cname.agilecrm.com." {
		return false
	}
	if strings.Contains(body, "Sorry, this page is no longer available.") {
		p.AddTag("Agile domain takeover", "dark", "https://www.agilecrm.com/custom-domains")
		a.session.Out.Warn("%s: vulnerable to takeover on Agile CRM\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectKinsta(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".kinsta.cloud.") {
		return false
	}
	if strings.Contains(body, "No Site For Domain") {
		p.AddTag("Kinsta domain takeover", "dark", "https://kinsta.com/knowledgebase/add-domain/")
		a.session.Out.Warn("%s: vulnerable to takeover on Kinsta\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectGemfury(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".furyns.com.") {
		return false
	}
	if strings.Contains(body, "404: This page could not be found.") {
		p.AddTag("Gemfury domain takeover", "dark", "https://gemfury.com/help/custom-domains/")
		a.session.Out.Warn("%s: vulnerable to takeover on Gemfury\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectLaunchRock(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".launchrock.com.") {
		return false
	}
	if strings.Contains(body, "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.") {
		p.AddTag("LaunchRock domain takeover", "dark", "https://help.launchrock.com/support/solutions/articles/1000087021-cname-general-instructions-for-creating-your-cname-record-")
		a.session.Out.Warn("%s: vulnerable to takeover on LaunchRock\n", p.URL)
	}
	return true
}


func (a *URLTakeoverDetector) detectBigCartel(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".bigcartel.com.") {
		return false
	}
	if strings.Contains(body, "<h1>Oops! We couldn&#8217;t find that page.</h1>") {
		p.AddTag("BigCartel domain takeover", "dark", "https://help.bigcartel.com/other-domain-providers")
		a.session.Out.Warn("%s: vulnerable to takeover on BigCartel\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectTeamWork(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".teamwork.com.") {
		return false
	}
	if strings.Contains(body, "Oops - We didn't find your site.") {
		p.AddTag("TeamWork domain takeover", "dark", "https://support.teamwork.com/projects/general-settings/using-a-custom-domain-name")
		a.session.Out.Warn("%s: vulnerable to takeover on TeamWork\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectShopify(p *core.Page, addrs []string, cname string, body string) bool {
	if !strings.HasSuffix(cname, ".myshopify.com.") {
		return false
	}
	if strings.Contains(body, "Sorry, this shop is currently unavailable.") {
		p.AddTag("Shopify domain takeover", "dark", "https://help.shopify.com/en/manual/online-store/domains/add-a-domain/using-existing-domains/connecting-domains")
		a.session.Out.Warn("%s: vulnerable to takeover on Shopify\n", p.URL)
	}
	return true
}

func (a *URLTakeoverDetector) detectBitbucket(p *core.Page, addrs []string, cname string, body string) bool {
        if !strings.HasSuffix(cname, ".bitbucket.io.") {
                return false
        }
        if strings.Contains(body, "Repository not found") {
                p.AddTag("Bitbucket domain takeover", "dark", "https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website-on-bitbucket-cloud/")
                a.session.Out.Warn("%s: vulnerable to takeover on Bitbucket\n", p.URL)
        }
        return true
}

func (a *URLTakeoverDetector) detectIntercom(p *core.Page, addrs []string, cname string, body string) bool {
        if !strings.HasSuffix(cname, "custom.intercom.help.") {
                return false
        }
        if strings.Contains(body, "This page is reserved for artistic dogs.") {
                p.AddTag("Intercom domain takeover", "dark", "https://developers.intercom.com/installing-intercom/docs/set-up-your-custom-domain")
                a.session.Out.Warn("%s: vulnerable to takeover on Intercom\n", p.URL)
        }
        return true
}
