package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ---------- identification through mDNS/SSDP ----------

// Plenty of home IoT devices announce themselves on the network over mDNS
// (port 5353) — a bulb, a Chromecast, a printer, all of them periodically
// shout the kind of service they offer. That is a much stronger signal
// than the MAC OUI or the hostname for answering "this really is a smart
// bulb". The answer also carries two names the rest of the scan often
// lacks: the host name ("sala.local") and the service instance, which is
// the name the user gave the device in its app ("TV do quarto").
var mdnsServiceMarkers = []struct{ marker, deviceType string }{
	{"_googlecast._tcp", "🔊 Assistente virtual / streaming (Chromecast/Google)"},
	{"_airplay._tcp", "🔊 Assistente virtual / streaming (AirPlay)"},
	{"_raop._tcp", "🔊 Assistente virtual / streaming (AirPlay áudio)"},
	{"_spotify-connect._tcp", "🔊 Assistente virtual / streaming (Spotify Connect)"},
	{"_hap._tcp", "💡 Dispositivo IoT (compatível com Apple HomeKit)"},
	{"_ipp._tcp", "🖨️ Impressora"},
	{"_printer._tcp", "🖨️ Impressora"},
	{"_pdl-datastream._tcp", "🖨️ Impressora"},
	{"_smb._tcp", "💻 Computador (compartilhamento de arquivos)"},
	{"_ssh._tcp", "💻 Computador/servidor (SSH)"},
	{"_workstation._tcp", "💻 Computador"},
	{"_home-sharing._tcp", "📺 Smart TV / media player"},
}

type mdnsInfo struct {
	Type     string // from the service types it answers for
	Hostname string // its own .local name, without the suffix
	Instance string // the service instance name, as set in the device's app
}

// parseMDNSResponse decodes an mDNS packet and keeps what a device says
// about itself. Only responses count: queries carry service names too — a
// phone looking for a Chromecast to cast YouTube asks for
// "_googlecast._tcp" — and reading those as announcements marked every
// such phone as a Chromecast.
//
// Only records about the sender are kept for the names: a response may
// also carry cached records about other hosts, and a host name is taken
// only from an address record that points back at the sender.
func parseMDNSResponse(packet []byte, from net.IP) (mdnsInfo, bool) {
	var dns layers.DNS
	if err := dns.DecodeFromBytes(packet, gopacket.NilDecodeFeedback); err != nil || !dns.QR {
		return mdnsInfo{}, false
	}
	var info mdnsInfo
	records := append(append(dns.Answers, dns.Authorities...), dns.Additionals...)
	for _, rr := range records {
		name := string(rr.Name)
		switch rr.Type {
		case layers.DNSTypeA:
			if rr.IP.Equal(from) && info.Hostname == "" {
				info.Hostname = cleanLabel(strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local"), 64)
			}
		case layers.DNSTypePTR:
			target := string(rr.PTR)
			if info.Type == "" {
				for _, m := range mdnsServiceMarkers {
					if strings.Contains(name, m.marker) || strings.Contains(target, m.marker) {
						info.Type = m.deviceType
						break
					}
				}
			}
			// "TV do quarto._googlecast._tcp.local" → "TV do quarto";
			// the service-type enumeration answers with bare types
			// ("_googlecast._tcp.local"), which are not instance names
			if i := strings.Index(target, "._"); i > 0 && info.Instance == "" && !strings.HasPrefix(name, "_services.") {
				info.Instance = cleanLabel(strings.ReplaceAll(target[:i], `\ `, " "), 60)
			}
		}
	}
	return info, info != mdnsInfo{}
}

var mdnsMu sync.RWMutex
var mdnsByIP = make(map[string]mdnsInfo)

func mdnsInfoFor(ip string) mdnsInfo {
	mdnsMu.RLock()
	defer mdnsMu.RUnlock()
	return mdnsByIP[ip]
}

func typeByMDNS(ip string) string { return mdnsInfoFor(ip).Type }

// record merges a new response into what is known about a host: a device
// answers per service, and each answer carries only part of the picture.
func (m mdnsInfo) mergeInto(ip string) {
	mdnsMu.Lock()
	defer mdnsMu.Unlock()
	cur := mdnsByIP[ip]
	if cur.Type == "" {
		cur.Type = m.Type
	}
	if cur.Hostname == "" {
		cur.Hostname = m.Hostname
	}
	if cur.Instance == "" {
		cur.Instance = m.Instance
	}
	mdnsByIP[ip] = cur
}

// mdnsQuery asks, in one packet, for every service type the markers know
// plus the DNS-SD enumeration. Devices only announce on their own when
// they join or change; asking makes them answer now, so a device that has
// been sitting quietly on the network since before the program started is
// identified in the first minute instead of whenever it next speaks up.
func mdnsQuery() []byte {
	dns := layers.DNS{ID: 0, RD: false}
	names := []string{"_services._dns-sd._udp.local"}
	for _, m := range mdnsServiceMarkers {
		names = append(names, m.marker+".local")
	}
	for _, n := range names {
		dns.Questions = append(dns.Questions, layers.DNSQuestion{
			Name: []byte(n), Type: layers.DNSTypePTR, Class: layers.DNSClassIN,
		})
	}
	buf := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		return nil
	}
	return buf.Bytes()
}

// startMDNSListener joins the multicast group every mDNS device uses
// (224.0.0.251:5353), listens to the answers circulating on the network,
// and every two minutes asks for them. The query goes out from port 5353
// itself, so the answers come back to the group and reach this same
// listener — and the rest of the network sees them too, as mDNS intends.
// If the port cannot be opened, identification by mDNS is simply off and
// the rest of the program carries on.
func startMDNSListener(iface string) {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println("mDNS: interface não encontrada, identificação por mDNS desativada:", err)
		return
	}
	group := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", ni, group)
	if err != nil {
		fmt.Println("mDNS: não consegui escutar (provavelmente já tem outro serviço na porta 5353) — identificação por mDNS desativada:", err)
		return
	}
	go func() {
		defer conn.Close()
		buf := make([]byte, 9000) // responses with many records exceed 4 KiB
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if info, ok := parseMDNSResponse(buf[:n], from.IP); ok {
				info.mergeInto(from.IP.String())
			}
		}
	}()
	go func() {
		query := mdnsQuery()
		for query != nil {
			conn.WriteToUDP(query, group)
			time.Sleep(2 * time.Minute)
		}
	}()
}

// SSDP (the same language we already speak to the router to find UPnP
// exposure) is also used by other devices around the house — smart TVs,
// speakers, cameras — to announce what they are. Here the search is broad
// (ST: ssdp:all) and looks at the text of any reply, not just the router's.
var ssdpTextMarkers = []struct{ marker, deviceType string }{
	{"chromecast", "🔊 Assistente virtual / streaming (Chromecast/Google)"},
	{"sonos", "🔊 Assistente virtual / streaming (Sonos)"},
	{"roku", "🔊 Assistente virtual / streaming (Roku)"},
	{"philips hue", "💡 Dispositivo IoT (Philips Hue)"},
	{"hue bridge", "💡 Dispositivo IoT (Philips Hue)"},
	{"mediarenderer", "📺 Smart TV / media player"},
	{"smart tv", "📺 Smart TV"},
	{"printer", "🖨️ Impressora"},
	{"camera", "🎥 Câmera IP"},
}

func identifyBySSDPText(text string) string {
	t := strings.ToLower(text)
	for _, m := range ssdpTextMarkers {
		if strings.Contains(t, m.marker) {
			return m.deviceType
		}
	}
	return ""
}

// generalSSDPScan sends a broad M-SEARCH (ssdp:all, rather than looking
// only for the router) and collects, for any device that answers inside
// the time window, the type its reply text suggests and the address of
// its UPnP description (validated — see descriptionURL).
func generalSSDPScan() (types, locations map[string]string) {
	result := make(map[string]string)
	locations = make(map[string]string)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return result, locations
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	target := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	search := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(search), target); err != nil {
		return result, locations
	}

	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout — no more replies
		}
		reply := string(buf[:n])
		ip := from.IP.String()
		if deviceType := identifyBySSDPText(reply); deviceType != "" {
			result[ip] = deviceType
		}
		// a device answers once per service it offers, all pointing at
		// the same description, so the first valid location is enough
		if _, seen := locations[ip]; !seen {
			if loc, ok := descriptionURL(ssdpHeader(reply, "LOCATION"), ip); ok {
				locations[ip] = loc
			}
		}
	}
	return result, locations
}

// ssdpHeader pulls one header out of an SSDP reply, which is an HTTP
// response over UDP. Header names are case-insensitive and devices do use
// every spelling.
func ssdpHeader(reply, name string) string {
	for _, line := range strings.Split(reply, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var ssdpMu sync.RWMutex
var ssdpTypeByIP = make(map[string]string)

func typeBySSDP(ip string) string {
	ssdpMu.RLock()
	defer ssdpMu.RUnlock()
	return ssdpTypeByIP[ip]
}

// startSSDPProbe repeats generalSSDPScan periodically (it is
// request/response, unlike mDNS which listens on its own) and refreshes
// the cache used for type identification.
func startSSDPProbe() {
	go func() {
		for {
			result, locations := generalSSDPScan()
			ssdpMu.Lock()
			for ip, deviceType := range result {
				ssdpTypeByIP[ip] = deviceType
			}
			ssdpMu.Unlock()
			// one at a time: there are rarely more than a dozen UPnP
			// devices in a home, and this loop has two minutes to spare
			for ip, loc := range locations {
				if d, ok := fetchUPnPDescription(loc); ok {
					upnpDescMu.Lock()
					upnpByIP[ip] = d
					upnpDescMu.Unlock()
				}
			}
			time.Sleep(2 * time.Minute)
		}
	}()
}
