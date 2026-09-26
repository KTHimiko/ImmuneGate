package main

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------- self-description: web admin page and UPnP ----------

// Type labels shared by the identification sources. The older tables in
// identification.go spell some of them out inline; these are the ones the
// newer sources use, kept identical to the originals so the dashboard
// shows one label per kind of device, whatever found it.
const (
	typePC        = "💻 Computador (PC/notebook)"
	typePhone     = "📱 Celular/tablet"
	typeIoT       = "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"
	typeCamera    = "🎥 Câmera IP"
	typePrinter   = "🖨️ Impressora"
	typeTV        = "📺 Smart TV / media player"
	typeStreaming = "🔊 Assistente virtual / streaming"
	typeNetwork   = "📶 Equipamento de rede (roteador/AP)"
	typeConsole   = "🎮 Videogame"
	typeNAS       = "🗄️ NAS / servidor de arquivos"
)

// textMarkers classifies the free text a device writes about itself: the
// title and Server header of its admin page, or the manufacturer and
// model in its UPnP description. Substrings are for names long enough not
// to collide; short words ("tv", "nvr") go in textTokens and must appear
// as a whole word, or "tv" would match inside every other string.
var textMarkers = []struct{ marker, deviceType string }{
	{"hikvision", typeCamera},
	{"dahua", typeCamera},
	{"netsurveillance", typeCamera},
	{"xmeye", typeCamera},
	{"dvrnvrdvs", typeCamera},           // the Basic-auth realm of countless DVRs
	{"/doc/page/login.asp", typeCamera}, // Hikvision's login redirect
	{"ip camera", typeCamera},
	{"webcam", typeCamera},
	{"network camera", typeCamera},
	{"laserjet", typePrinter},
	{"officejet", typePrinter},
	{"deskjet", typePrinter},
	{"epson", typePrinter},
	{"brother", typePrinter},
	{"printer", typePrinter},
	{"impressora", typePrinter},
	{"tp-link", typeNetwork},
	{"tplink", typeNetwork},
	{"mikrotik", typeNetwork},
	{"routeros", typeNetwork},
	{"openwrt", typeNetwork},
	{"dd-wrt", typeNetwork},
	{"unifi", typeNetwork},
	{"fiberhome", typeNetwork},
	{"zxhn", typeNetwork}, // ZTE fibre ONTs
	{"roteador", typeNetwork},
	{"router", typeNetwork},
	{"access point", typeNetwork},
	{"webos", typeTV},
	{"tizen", typeTV},
	{"bravia", typeTV},
	{"smart tv", typeTV},
	{"roku", typeStreaming},
	{"sonos", typeStreaming},
	{"chromecast", typeStreaming},
	{"synology", typeNAS},
	{"diskstation", typeNAS},
	{"qnap", typeNAS},
	{"tasmota", typeIoT},
	{"esphome", typeIoT},
	{"shelly", typeIoT},
	{"sonoff", typeIoT},
	{"philips hue", typeIoT},
}

var textTokens = map[string]string{
	"nvr": typeCamera, "dvr": typeCamera, "ipc": typeCamera, "camera": typeCamera, "câmera": typeCamera,
	"tv":  typeTV,
	"nas": typeNAS,
	"ap":  typeNetwork, "gateway": typeNetwork, "modem": typeNetwork,
}

var nonWord = regexp.MustCompile(`[^\p{L}\p{N}]+`)

func classifyByText(text string) string {
	t := strings.ToLower(text)
	if strings.TrimSpace(t) == "" {
		return ""
	}
	for _, m := range textMarkers {
		if strings.Contains(t, m.marker) {
			return m.deviceType
		}
	}
	for _, tok := range nonWord.Split(t, -1) {
		if dt, ok := textTokens[tok]; ok {
			return dt
		}
	}
	return ""
}

// ---- web admin page ----

// A device with a web port open almost always serves an admin page, and
// that page names the product: "Hikvision", "TP-LINK Archer C6", "HP
// LaserJet". The request is an ordinary GET / — the same thing a browser
// does — and nothing is followed or submitted.
type webBanner struct {
	Title string // what goes on the card as the model
	Text  string // everything classifiable: title, Server, realm, redirect target
}

var bannerClient = &http.Client{
	Timeout: 2 * time.Second,
	// the redirect target is itself a clue (Hikvision answers with
	// /doc/page/login.asp) and following it could leave the device
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		// home devices serve self-signed certificates as a rule; this
		// only reads a page title, it sends nothing that needs protecting
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func fetchBanner(pageURL string) (webBanner, bool) {
	resp, err := bannerClient.Get(pageURL)
	if err != nil {
		return webBanner{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))

	var b webBanner
	if m := titleRe.FindSubmatch(body); m != nil {
		b.Title = cleanLabel(html.UnescapeString(string(m[1])), 60)
	}
	b.Text = strings.Join([]string{
		b.Title,
		resp.Header.Get("Server"),
		resp.Header.Get("WWW-Authenticate"),
		resp.Header.Get("Location"),
	}, " ")
	return b, true
}

// cleanLabel collapses whitespace and control characters and caps the
// length: this text comes from the device and ends up on the dashboard.
func cleanLabel(s string, max int) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == ' ' || r == '\u00a0'
	}), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return s
}

type bannerEntry struct {
	banner webBanner
	at     time.Time
}

var bannerMu sync.Mutex
var bannerCache = map[string]bannerEntry{}

// bannerTTL: a page title does not change between scans, and without a
// cache every 20-second cycle would send a GET to every device with a
// web port.
const bannerTTL = 10 * time.Minute

func httpBannerFor(ip string, openPorts []string) webBanner {
	bannerMu.Lock()
	if e, ok := bannerCache[ip]; ok && time.Since(e.at) < bannerTTL {
		bannerMu.Unlock()
		return e.banner
	}
	bannerMu.Unlock()

	open := map[string]bool{}
	for _, p := range openPorts {
		open[p] = true
	}
	var b webBanner
	for _, c := range []struct{ port, scheme string }{
		{"80", "http"}, {"8080", "http"}, {"443", "https"}, {"8443", "https"},
	} {
		if !open[c.port] {
			continue
		}
		if got, ok := fetchBanner(fmt.Sprintf("%s://%s:%s/", c.scheme, ip, c.port)); ok {
			b = got
			break
		}
	}
	// failures are cached too, so a device that never answers is not
	// retried on every cycle
	bannerMu.Lock()
	bannerCache[ip] = bannerEntry{b, time.Now()}
	bannerMu.Unlock()
	return b
}

// ---- UPnP device description ----

// An SSDP reply carries a LOCATION header pointing at an XML document in
// which the device describes itself — friendly name, manufacturer, model
// and a standard device type. It is the most specific thing a device ever
// says about itself on a home network.
type upnpDescription struct {
	DeviceType   string
	FriendlyName string
	Manufacturer string
	ModelName    string
}

func (d upnpDescription) deviceTypeGuess() string {
	if t := classifyByText(d.Manufacturer + " " + d.ModelName + " " + d.FriendlyName); t != "" {
		return t
	}
	switch u := d.DeviceType; {
	case strings.Contains(u, ":MediaRenderer:"):
		return typeTV
	case strings.Contains(u, ":InternetGatewayDevice:"), strings.Contains(u, ":WANDevice:"), strings.Contains(u, ":WFADevice:"):
		return typeNetwork
	case strings.Contains(u, ":Printer:"):
		return typePrinter
	case strings.Contains(u, ":DigitalSecurityCamera:"):
		return typeCamera
	case strings.Contains(u, ":MediaServer:"):
		return typeNAS
	}
	return ""
}

// label is what goes on the card: the friendly name, with the model when
// the name does not already contain it.
func (d upnpDescription) label() string {
	name, model := d.FriendlyName, d.ModelName
	switch {
	case name == "":
		return strings.TrimSpace(d.Manufacturer + " " + model)
	case model != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(model)):
		return name + " (" + model + ")"
	}
	return name
}

func parseUPnPDescription(r io.Reader) (upnpDescription, error) {
	var doc struct {
		Device struct {
			DeviceType   string `xml:"deviceType"`
			FriendlyName string `xml:"friendlyName"`
			Manufacturer string `xml:"manufacturer"`
			ModelName    string `xml:"modelName"`
		} `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(r, 64<<10)).Decode(&doc); err != nil {
		return upnpDescription{}, err
	}
	d := doc.Device
	return upnpDescription{
		DeviceType:   cleanLabel(d.DeviceType, 120),
		FriendlyName: cleanLabel(d.FriendlyName, 60),
		Manufacturer: cleanLabel(d.Manufacturer, 40),
		ModelName:    cleanLabel(d.ModelName, 40),
	}, nil
}

// descriptionURL validates a LOCATION header before anything is fetched.
// The header is written by whoever answered the multicast search, so it
// could name any address — including a host outside the network, which
// would turn the scanner into a relay for requests the user never meant
// to make. Only plain HTTP on the very address that answered is accepted.
func descriptionURL(location, responder string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil || u.Scheme != "http" || u.Hostname() != responder {
		return "", false
	}
	return u.String(), true
}

func fetchUPnPDescription(location string) (upnpDescription, bool) {
	resp, err := bannerClient.Get(location)
	if err != nil {
		return upnpDescription{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return upnpDescription{}, false
	}
	d, err := parseUPnPDescription(resp.Body)
	return d, err == nil
}

var upnpDescMu sync.RWMutex
var upnpByIP = map[string]upnpDescription{}

func upnpDescriptionFor(ip string) upnpDescription {
	upnpDescMu.RLock()
	defer upnpDescMu.RUnlock()
	return upnpByIP[ip]
}
