package agents

import (
	"context"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/shelld3v/aquatone/core"
)

type URLScreenshotter struct {
	session    *core.Session
	chromePath string
}

func NewURLScreenshotter() *URLScreenshotter {
	return &URLScreenshotter{}
}

func (a *URLScreenshotter) ID() string {
	return "agent:url_screenshotter"
}

func (a *URLScreenshotter) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	a.session = s

	return nil
}

func (a *URLScreenshotter) OnURLResponsive(url string) {
	a.session.Out.Debug("[%s] Received new responsive URL %s\n", a.ID(), url)
	page := a.session.GetPage(url)
	if page == nil {
		a.session.Out.Error("Unable to find page for URL: %s\n", url)
		return
	}

	a.session.WaitGroup.Add()
	go func(page *core.Page) {
		defer a.session.WaitGroup.Done()
		a.screenshotPage(page)
	}(page)
}

// execAllocator turns the chrome instance allocator options into a derivative context.Context
func (a URLScreenshotter) execAllocator(parent context.Context) (context.Context, context.CancelFunc) {
	options := []chromedp.ExecAllocatorOption{}

	if a.session.Options.Proxy != "" {
		options = append(options, chromedp.ProxyServer(a.session.Options.Proxy))
	}

	if a.session.Options.ChromePath != "" {
		options = append(options, chromedp.ExecPath(a.session.Options.ChromePath))
	}

	if a.session.Options.ThumbnailSize != "" {
		Thumbsize := strings.Split(a.session.Options.ThumbnailSize, ",")
		Width, _ := strconv.Atoi(Thumbsize[0])
		Height, _ := strconv.Atoi(Thumbsize[1])
		options = append(options, chromedp.WindowSize(Width, Height))
	}

	options = append(options, chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"))
	options = append(options, chromedp.DisableGPU)
	options = append(options, chromedp.Headless)
	options = append(options, chromedp.NoFirstRun)
	options = append(options, chromedp.NoDefaultBrowserCheck)
	options = append(options, chromedp.Flag("disable-crash-reporter", true))
	options = append(options, chromedp.Flag("disable-extensions", true))
	options = append(options, chromedp.Flag("disable-notifications", true))
	options = append(options, chromedp.Flag("disable-infobars", true))
	options = append(options, chromedp.Flag("disable-features", "VizDisplayCompositor"))
	options = append(options, chromedp.Flag("incognito", true))
	options = append(options, chromedp.Flag("ignore-certificate-errors", true))

	return chromedp.NewExecAllocator(parent, options...)
}

func (a *URLScreenshotter) screenshotPage(p *core.Page) {
	filePath := fmt.Sprintf("screenshots/%s.png", p.BaseFilename())

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.session.Options.ScreenshotTimeout)*time.Millisecond)
	defer cancel()

	ctx, cancel = a.execAllocator(ctx)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			a.session.Stats.IncrementScreenshotFailed()
			a.session.Out.Debug("[%s] %s: screenshot failed: alert box popped up\n", a.ID(), p.URL)
			return
		}
	})

	var pic []byte
	var res *runtime.RemoteObject
	var err error

	headers := make(map[string]interface{})
	for _, h := range a.session.Options.HTTPHeaders {
		header := strings.SplitN(h, ":", 2)
		if len(header) > 1 {
			headers[header[0]] = header[1]
		}
	}

	if a.session.Options.FullPage {
		// Source: https://github.com/chromedp/examples/blob/master/screenshot/main.go
		err = chromedp.Run(ctx, chromedp.Tasks{
			network.Enable(),
			network.SetExtraHTTPHeaders(network.Headers(headers)),
			chromedp.Navigate(p.URL),
			chromedp.Sleep(time.Duration(a.session.Options.ScreenshotDelay) * time.Millisecond),
			chromedp.EvaluateAsDevTools(`window.alert = window.confirm = window.prompt = function (txt){return txt}`, &res),
			chromedp.FullScreenshot(&pic, 100),
		})
	} else {
		err = chromedp.Run(ctx, chromedp.Tasks{
			network.Enable(),
			network.SetExtraHTTPHeaders(network.Headers(headers)),
			chromedp.Navigate(p.URL),
			chromedp.Sleep(time.Duration(a.session.Options.ScreenshotDelay) * time.Millisecond),
			chromedp.EvaluateAsDevTools(`window.alert = window.confirm = window.prompt = function (txt){return txt}`, &res),
			chromedp.CaptureScreenshot(&pic),
		})
	}

	if err != nil {
		a.session.Out.Debug("[%s] Screenshot failed for %s: %v\n", a.ID(), p.URL, err)
		a.session.Stats.IncrementScreenshotFailed()
		a.session.Out.Error("%s: %s\n", p.URL, Red("screenshot failed"))
		return
	}

	if err := ioutil.WriteFile(a.session.GetFilePath(filePath), pic, 0700); err != nil {
		a.session.Out.Debug("[%s] Screenshot failed for %s: %v\n", a.ID(), p.URL, err)
		a.session.Stats.IncrementScreenshotFailed()
		a.session.Out.Error("%s: %s\n", p.URL, Red("screenshot failed"))
		return
	}

	a.session.Out.Debug("[%s] Screenshotted successfully for %s\n", a.ID(), p.URL)
	a.session.Stats.IncrementScreenshotSuccessful()
	a.session.Out.Info("%s: %s\n", p.URL, Green("screenshot successful"))
	p.ScreenshotPath = filePath
	p.HasScreenshot = true
}
