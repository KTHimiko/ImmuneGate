package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseOUIRegistry(t *testing.T) {
	ieee := `OUI/MA-L                                                    Organization
company_id                                                  Organization
                                                            Address

28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd.
286FB9     (base 16)		Nokia Shanghai Bell Co., Ltd.
				No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai
24-6F-28   (hex)		Espressif Inc.
`
	nmap := "B827EB Raspberry Pi Foundation\n# comentário\n"

	reg := parseOUIRegistry(strings.NewReader(ieee + nmap))
	want := map[string]string{
		"286FB9": "Nokia Shanghai Bell Co., Ltd.",
		"246F28": "Espressif Inc.",
		"B827EB": "Raspberry Pi Foundation",
	}
	if len(reg) != len(want) {
		t.Errorf("esperava %d prefixos, obtive %d: %v", len(want), len(reg), reg)
	}
	for k, v := range want {
		if reg[k] != v {
			t.Errorf("%s: %q, queria %q", k, reg[k], v)
		}
	}
}

func TestLookupByMACUsesRegistry(t *testing.T) {
	saved := ouiRegistry
	defer func() { ouiRegistry = saved }()
	ouiRegistry = map[string]string{"A1B2C3": "Hangzhou Hikvision Digital Technology Co.,Ltd.", "D4E5F6": "Samsung Electronics Co.,Ltd"}

	if v, dt := lookupByMAC("a1:b2:c3:00:00:01"); !strings.Contains(v, "Hikvision") || dt != typeCamera {
		t.Errorf("Hikvision: fabricante %q, tipo %q", v, dt)
	}
	// Samsung makes phones, TVs and appliances: vendor yes, type no
	if v, dt := lookupByMAC("d4:e5:f6:00:00:01"); !strings.Contains(v, "Samsung") || dt != "" {
		t.Errorf("Samsung: fabricante %q, tipo %q (não deveria chutar tipo)", v, dt)
	}
	// the curated table still wins over the registry
	if _, dt := lookupByMAC("B8:27:EB:00:00:01"); !strings.Contains(dt, "Raspberry") {
		t.Errorf("tabela embutida deveria prevalecer, obtive %q", dt)
	}
	if v, _ := lookupByMAC("02:00:00:00:00:01"); v != "Desconhecido" {
		t.Errorf("prefixo fora de tudo deveria ser Desconhecido, obtive %q", v)
	}
}

func TestRefineTypeByHostname(t *testing.T) {
	cases := []struct{ host, want string }{
		{"MacBook-de-Camila", "💻 Computador (PC/notebook)"}, // was "Câmera IP" by the "cam" substring
		{"Camila-celular", ""},
		{"ipcam-sala", "🎥 Câmera IP"},
		{"webcam", "🎥 Câmera IP"},
		{"camera-garagem", "🎥 Câmera IP"},
		{"ESP_3A2B1C", typeIoT},
		{"tasmota-4F21", typeIoT},
		{"PS5-123", typeConsole},
		{"raspberrypi", "🍓 Raspberry Pi / placa de projeto"},
		{"Galaxy-S21", "📱 Celular/tablet"},
	}
	for _, c := range cases {
		if got := refineTypeByHostname(c.host); got != c.want {
			t.Errorf("%q: %q, queria %q", c.host, got, c.want)
		}
	}
}

func TestClassifyByText(t *testing.T) {
	cases := []struct{ text, want string }{
		{"Hikvision-Webs", typeCamera},
		{`Basic realm="DVRNVRDVS"`, typeCamera},
		{"/doc/page/login.asp?_1690000000", typeCamera},
		{"[TV] Samsung 7 Series (55)", typeTV},
		{"TL-WR840N TP-LINK Wireless Router", typeNetwork},
		{"HP LaserJet Pro M404", typePrinter},
		{"Synology DiskStation", typeNAS},
		// "tv" and "ap" only as whole words
		{"Tvheadend Apache", ""},
		{"Login", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := classifyByText(c.text); got != c.want {
			t.Errorf("%q: %q, queria %q", c.text, got, c.want)
		}
	}
}

func TestTypeByDHCPVendorClass(t *testing.T) {
	cases := []struct{ vc, want string }{
		{"android-dhcp-14", "📱 Celular/tablet (Android)"},
		{"MSFT 5.0", "💻 Computador (Windows)"},
		{"udhcp 1.36.1", "💡 Dispositivo embarcado (Linux/BusyBox)"},
		{"dhcpcd-9.4.1:Linux", ""}, // Linux on anything: says nothing about the device
		{"", ""},
	}
	for _, c := range cases {
		if got := typeByDHCPVendorClass(c.vc); got != c.want {
			t.Errorf("%q: %q, queria %q", c.vc, got, c.want)
		}
	}
}

func TestParseUPnPDescription(t *testing.T) {
	x := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Sala de estar</friendlyName>
    <manufacturer>LG Electronics</manufacturer>
    <modelName>OLED55C1</modelName>
  </device>
</root>`
	d, err := parseUPnPDescription(strings.NewReader(x))
	if err != nil {
		t.Fatal(err)
	}
	if d.Manufacturer != "LG Electronics" || d.ModelName != "OLED55C1" {
		t.Errorf("campos lidos errado: %+v", d)
	}
	// nothing in the names says TV; the standard device type does
	if got := d.deviceTypeGuess(); got != typeTV {
		t.Errorf("tipo %q, queria %q", got, typeTV)
	}
	if got := d.label(); got != "Sala de estar (OLED55C1)" {
		t.Errorf("rótulo %q", got)
	}
}

func TestDescriptionURLOnlyFromResponder(t *testing.T) {
	cases := []struct {
		loc, from string
		ok        bool
	}{
		{"http://192.168.0.20:49152/desc.xml", "192.168.0.20", true},
		// a reply pointing somewhere else would make us fetch it
		{"http://203.0.113.9/desc.xml", "192.168.0.20", false},
		{"http://192.168.0.21:49152/desc.xml", "192.168.0.20", false},
		{"file:///etc/passwd", "192.168.0.20", false},
		{"https://192.168.0.20/desc.xml", "192.168.0.20", false},
		{"", "192.168.0.20", false},
	}
	for _, c := range cases {
		if _, ok := descriptionURL(c.loc, c.from); ok != c.ok {
			t.Errorf("%q vindo de %s: aceito=%v, queria %v", c.loc, c.from, ok, c.ok)
		}
	}
}

func TestSSDPHeader(t *testing.T) {
	reply := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nlocation: http://192.168.0.1:1900/igd.xml\r\nST: upnp:rootdevice\r\n\r\n"
	if got := ssdpHeader(reply, "LOCATION"); got != "http://192.168.0.1:1900/igd.xml" {
		t.Errorf("LOCATION: %q", got)
	}
}

func TestFetchBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Hikvision-Webs")
		w.Write([]byte("<html><head><title>\n  Web&nbsp;Login\n</title></head></html>"))
	}))
	defer srv.Close()

	b, ok := fetchBanner(srv.URL + "/")
	if !ok {
		t.Fatal("não leu a página")
	}
	if b.Title != "Web Login" {
		t.Errorf("título %q", b.Title)
	}
	if classifyByText(b.Text) != typeCamera {
		t.Errorf("deveria reconhecer a câmera pelo cabeçalho Server: %q", b.Text)
	}
}

func TestFetchBannerDoesNotFollowRedirect(t *testing.T) {
	followed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/doc/page/login.asp" {
			followed = true
		}
		http.Redirect(w, r, "/doc/page/login.asp", http.StatusFound)
	}))
	defer srv.Close()

	b, _ := fetchBanner(srv.URL + "/")
	if followed {
		t.Error("seguiu o redirecionamento")
	}
	// the redirect target alone gives the camera away
	if classifyByText(b.Text) != typeCamera {
		t.Errorf("o destino do redirecionamento deveria bastar: %q", b.Text)
	}
}

// The order matters more than any single rule: what the device says about
// itself has to beat what is inferred from its MAC or its ports.
func TestIdentifyDevicePrecedence(t *testing.T) {
	savedReg, savedUPnP, savedDHCP := ouiRegistry, upnpByIP, dhcpClients
	defer func() { ouiRegistry, upnpByIP, dhcpClients = savedReg, savedUPnP, savedDHCP }()
	ouiRegistry = map[string]string{"A1B2C3": "Espressif Inc."}
	upnpByIP = map[string]upnpDescription{}
	dhcpClients = map[string]dhcpClient{}

	// MAC vendor alone
	r := deviceResult{IP: "10.0.0.5", MAC: "a1:b2:c3:00:00:05", Trusted: true}
	identifyDevice(&r)
	if r.ProbableType != typeIoT || r.IdentifiedBy != "fabricante do MAC" {
		t.Errorf("só OUI: %q por %q", r.ProbableType, r.IdentifiedBy)
	}

	// the device's own UPnP description overrides the MAC vendor
	upnpByIP["10.0.0.5"] = upnpDescription{DeviceType: "urn:schemas-upnp-org:device:MediaRenderer:1", FriendlyName: "TV do quarto"}
	r = deviceResult{IP: "10.0.0.5", MAC: "a1:b2:c3:00:00:05", Trusted: true}
	identifyDevice(&r)
	if r.ProbableType != typeTV || r.IdentifiedBy != "descrição UPnP" || r.Model != "TV do quarto" {
		t.Errorf("UPnP: %q por %q, modelo %q", r.ProbableType, r.IdentifiedBy, r.Model)
	}

	// a phone with a randomized MAC, known only through its DHCP request
	dhcpClients["da:a1:19:44:55:66"] = dhcpClient{Hostname: "Moto-G84", VendorClass: "android-dhcp-14"}
	r = deviceResult{IP: "10.0.0.9", MAC: "DA:A1:19:44:55:66", Trusted: true}
	identifyDevice(&r)
	if r.Hostname != "Moto-G84" {
		t.Errorf("o nome pedido no DHCP deveria preencher o hostname, obtive %q", r.Hostname)
	}
	if r.ProbableType != "📱 Celular/tablet (Android)" || !strings.HasPrefix(r.IdentifiedBy, "cliente DHCP") {
		t.Errorf("DHCP: %q por %q", r.ProbableType, r.IdentifiedBy)
	}

	// nothing at all but the randomized bit
	r = deviceResult{IP: "10.0.0.10", MAC: "DA:00:00:00:00:10", Trusted: true}
	identifyDevice(&r)
	if r.IdentifiedBy != "MAC aleatório" {
		t.Errorf("último recurso: %q por %q", r.ProbableType, r.IdentifiedBy)
	}
}
