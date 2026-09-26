package main

import (
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func mdnsPacket(t *testing.T, dns layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseMDNSResponse(t *testing.T) {
	from := net.ParseIP("192.168.0.30").To4()
	resp := mdnsPacket(t, layers.DNS{
		QR: true, AA: true,
		Answers: []layers.DNSResourceRecord{{
			Name: []byte("_googlecast._tcp.local"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN, TTL: 120,
			PTR: []byte("TV do quarto._googlecast._tcp.local"),
		}},
		Additionals: []layers.DNSResourceRecord{
			// a record about someone else, cached by the sender: not its name
			{Name: []byte("vizinho.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 120, IP: net.ParseIP("192.168.0.99").To4()},
			{Name: []byte("chromecast-sala.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 120, IP: from},
		},
	})

	info, ok := parseMDNSResponse(resp, from)
	if !ok {
		t.Fatal("resposta válida não reconhecida")
	}
	if info.Type != "🔊 Assistente virtual / streaming (Chromecast/Google)" {
		t.Errorf("tipo %q", info.Type)
	}
	if info.Instance != "TV do quarto" {
		t.Errorf("instância %q", info.Instance)
	}
	if info.Hostname != "chromecast-sala" {
		t.Errorf("hostname %q (não pode vir do registro de outro host)", info.Hostname)
	}
}

// The bug this replaced: a phone asking for Chromecasts was itself marked
// as a Chromecast, because the query carries the same service name.
func TestParseMDNSIgnoresQueries(t *testing.T) {
	query := mdnsPacket(t, layers.DNS{
		QR: false,
		Questions: []layers.DNSQuestion{{
			Name: []byte("_googlecast._tcp.local"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN,
		}},
	})
	if info, ok := parseMDNSResponse(query, net.ParseIP("192.168.0.31")); ok {
		t.Errorf("uma pergunta foi lida como anúncio: %+v", info)
	}
	if _, ok := parseMDNSResponse([]byte("lixo"), net.ParseIP("192.168.0.31")); ok {
		t.Error("pacote inválido não deveria ser aceito")
	}
}

func TestMDNSQueryIsAQuery(t *testing.T) {
	q := mdnsQuery()
	var dns layers.DNS
	if err := dns.DecodeFromBytes(q, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	// our own query loops back to the listener; it must not identify us
	if dns.QR || len(dns.Questions) != len(mdnsServiceMarkers)+1 {
		t.Errorf("QR=%v, %d perguntas", dns.QR, len(dns.Questions))
	}
}

func TestParseIPv6Neighbours(t *testing.T) {
	out := `2804:14c:5b:8000::1f lladdr 1a:2b:3c:4d:5e:6f STALE
fe80::1a2b:3cff:fe4d:5e6f lladdr 1a:2b:3c:4d:5e:6f router REACHABLE
fe80::99 FAILED
fe80::aa INCOMPLETE
ff02::1 lladdr 33:33:00:00:00:01 NOARP
fe80::77 lladdr 02:00:00:00:00:77 DELAY
`
	got := parseIPv6Neighbours(out)
	if len(got) != 2 {
		t.Fatalf("esperava 2 MACs, obtive %d: %v", len(got), got)
	}
	a := got["1a:2b:3c:4d:5e:6f"]
	// link-local first: the stable name for a device whose global
	// addresses rotate
	if len(a) != 2 || a[0] != "fe80::1a2b:3cff:fe4d:5e6f" {
		t.Errorf("endereços %v", a)
	}
}

func TestMergeIPv6(t *testing.T) {
	gw, _ := net.ParseMAC("aa:aa:aa:aa:aa:01")
	own, _ := net.ParseMAC("aa:aa:aa:aa:aa:02")
	known, _ := net.ParseMAC("aa:aa:aa:aa:aa:03")
	n := &networkInfo{GatewayMAC: gw, MAC: own}
	arp := map[string]net.HardwareAddr{"192.168.0.3": known}
	results := []deviceResult{{IP: "192.168.0.3", MAC: known.String(), Trusted: true}}
	v6 := map[string][]string{
		known.String():      {"fe80::3"},
		gw.String():         {"fe80::1"},
		own.String():        {"fe80::2"},
		"aa:aa:aa:aa:aa:09": {"fe80::9", "2804::9"},
	}

	out := mergeIPv6(n, results, arp, v6)
	if len(out) != 2 {
		t.Fatalf("esperava o conhecido + 1 só-IPv6, obtive %d", len(out))
	}
	if len(out[0].IPv6) != 1 || out[0].IPv6Only {
		t.Errorf("o IPv6 deveria ser anexado ao dispositivo já conhecido: %+v", out[0])
	}
	if !out[1].IPv6Only || out[1].IP != "fe80::9" {
		t.Errorf("só-IPv6 mal montado: %+v", out[1])
	}
	if v := evaluateAdmission(out[1]); !v.Allowed {
		t.Errorf("política não pode reprovar o que não consegue conter: %s", v.Reason)
	}
}

func TestIPv6OnlyCardHasNoIsolateButton(t *testing.T) {
	r := deviceResult{IP: "fe80::9", MAC: "aa:aa:aa:aa:aa:09", IPv6: []string{"fe80::9"}, IPv6Only: true, Risk: "baixo"}
	card := deviceCard(r, buildRiskContext([]deviceResult{r}))
	if strings.Contains(card, `action="/isolar"`) {
		t.Error("não pode oferecer isolar o que o ARP não alcança")
	}
	if !strings.Contains(card, "só IPv6") {
		t.Error("faltou o selo só IPv6")
	}
}

// The output that made the program scan an empty Wi-Fi while all the
// devices were on the cable.
func TestChooseRoutePrefersLowestMetric(t *testing.T) {
	out := "default via 192.168.2.1 dev enp0s31f6 proto dhcp src 192.168.2.156 metric 100 \n" +
		"default via 10.174.52.6 dev wlan0 proto dhcp src 10.174.52.139 metric 600 \n"
	routes := parseDefaultRoutes(out)
	if len(routes) != 2 {
		t.Fatalf("esperava 2 rotas, obtive %v", routes)
	}
	r, err := chooseRoute(routes, "")
	if err != nil || r.iface != "enp0s31f6" || r.gateway != "192.168.2.1" {
		t.Errorf("escolheu %+v (%v), queria o cabo", r, err)
	}
	// the order in the output must not matter
	r, _ = chooseRoute([]defaultRoute{routes[1], routes[0]}, "")
	if r.iface != "enp0s31f6" {
		t.Errorf("com a ordem invertida escolheu %s", r.iface)
	}
	r, err = chooseRoute(routes, "wlan0")
	if err != nil || r.gateway != "10.174.52.6" {
		t.Errorf("INTERFACE=wlan0: %+v (%v)", r, err)
	}
	if _, err := chooseRoute(routes, "eth9"); err == nil || !strings.Contains(err.Error(), "enp0s31f6") {
		t.Errorf("interface inexistente deveria listar as disponíveis: %v", err)
	}
	// a VPN default route has no gateway and is skipped
	if got := parseDefaultRoutes("default dev tun0 scope link\n"); len(got) != 0 {
		t.Errorf("rota sem gateway deveria ser ignorada: %v", got)
	}
}
