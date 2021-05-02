package agents

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"
	"strings"
	"strconv"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/shelld3v/aquatone/core"
)

type URLScreenshotter struct {
	session         *core.Session
	chromePath      string
	tempUserDirPath string
}

func NewURLScreenshotter() *URLScreenshotter {
	return &URLScreenshotter{}
}

func (a *URLScreenshotter) ID() string {
	return "agent:url_screenshotter"
}

func (a *URLScreenshotter) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	s.EventBus.SubscribeAsync(core.SessionEnd, a.OnSessionEnd, false)
	a.session = s
	a.createTempUserDir()

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

func (a *URLScreenshotter) OnSessionEnd() {
	a.session.Out.Debug("[%s] Received SessionEnd event\n", a.ID())
	os.RemoveAll(a.tempUserDirPath)
	a.session.Out.Debug("[%s] Deleted temporary user directory at: %s\n", a.ID(), a.tempUserDirPath)
}

func (a *URLScreenshotter) createTempUserDir() {
	dir, err := ioutil.TempDir("", "aquatone-chrome")
	if err != nil {
		a.session.Out.Fatal("Unable to create temporary user directory for Chrome/Chromium browser\n")
		os.Exit(1)
	}
	a.session.Out.Debug("[%s] Created temporary user directory at: %s\n", a.ID(), dir)
	a.tempUserDirPath = dir
}

func (a URLScreenshotter) getOpts() (options []chromedp.ExecAllocatorOption) {
	options = []chromedp.ExecAllocatorOption{}

	if *a.session.Options.Proxy != "" {
		options = append(options, chromedp.ProxyServer(*a.session.Options.Proxy))
	}

	if *a.session.Options.ChromePath != "" {
		options = append(options, chromedp.ExecPath(*a.session.Options.ChromePath))
	}

	if *a.session.Options.Resolution != "" {
		Resolutions := strings.Split(*a.session.Options.Resolution, ",")
		ResolutionX, _ := strconv.Atoi(Resolutions[0])
		ResolutionY, _ := strconv.Atoi(Resolutions[1])
		options = append(options, chromedp.WindowSize(ResolutionX, ResolutionY))
	}

	options = append(options, chromedp.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"))
	options = append(options, chromedp.DisableGPU)
	options = append(options, chromedp.Flag("ignore-certificate-errors", true))

	return options
}

// execAllocator turns a.getOpts() (the chrome instance allocator options) into a derivative context.Context
func (a URLScreenshotter) execAllocator(parent context.Context) (context.Context, context.CancelFunc) {
	return chromedp.NewExecAllocator(parent, a.getOpts()...)
}

func (a *URLScreenshotter) screenshotPage(p *core.Page) {
	filePath := fmt.Sprintf("screenshots/%s.png", p.BaseFilename())

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*a.session.Options.ScreenshotTimeout)*time.Millisecond)
	defer cancel()

	ctx, cancel := a.execAllocator(ctx)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			a.session.Out.Debug("%s Error: alert box found\n", a.ID)
			a.session.Stats.IncrementScreenshotFailed()
			a.session.Out.Error("%s: screenshot failed: alert box popped up\n", p.URL)
			return
		}
	})


	var pic []byte
	var res interface{}

	if err := chromedp.Run(ctx, chromedp.Tasks{
		chromedp.Navigate(p.URL),
		chromedp.Sleep(time.Duration(*a.session.Options.ScreenshotDelay)*time.Millisecond),
		chromedp.CaptureScreenshot(&pic),
		chromedp.EvaluateAsDevTools(`window.alert = window.confirm = window.prompt = function (txt){return txt}`, &res),
	}); err != nil {
		a.session.Out.Debug("%s Error: %v\n", a.ID, err)
		a.session.Stats.IncrementScreenshotFailed()
		a.session.Out.Error("%s: screenshot failed: %s\n", p.URL, err)
		return
	}

	if err := ioutil.WriteFile(filePath, pic, 0700); err != nil {
		a.session.Out.Debug("%s Error: %v\n", a.ID(), err)
		a.session.Stats.IncrementScreenshotFailed()
		a.session.Out.Error("%s: screenshot failed: %s\n", p.URL, err)
		return
	}

	a.session.Stats.IncrementScreenshotSuccessful()
	a.session.Out.Info("%s: %s\n", p.URL, Green("screenshot successful"))
	p.ScreenshotPath = filePath
	p.HasScreenshot = true
}

func (a *URLScreenshotter) killChromeProcessIfRunning(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	cmd.Process.Release()
	cmd.Process.Kill()
}
