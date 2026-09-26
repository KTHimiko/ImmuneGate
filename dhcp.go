package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ---------- rogue DHCP server detection ----------

// The ARP spoofing we already detect (checkGatewaySpoofing) has to be
// aimed at one device at a time. A rogue DHCP server is more powerful: put
// a second server on the network and, if it answers faster than the real
// router, it hands a forged gateway and DNS to every new device that joins
// from then on — with no need to poison anyone's ARP. It is a classic
// network attack that none of our other detections covers.
var dhcpMu sync.Mutex
var knownDHCPServers = make(map[string]bool)
var dhcpLearningPeriod = true

// startRogueDHCPDetection passively listens to DHCP traffic (ports 67 and
// 68) and, during the first 60 seconds, learns which IPs already answer as
// servers on the network — that becomes the trust baseline, and it even
// copes with unusual setups that legitimately run more than one DHCP
// server, as long as they are active from the start. After that period,
// any new server showing up raises an alert.
func startRogueDHCPDetection(iface string) {
	handle, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		fmt.Println("Detecção de DHCP falso desativada (não consegui abrir a interface):", err)
		return
	}
	if err := handle.SetBPFFilter("udp and (port 67 or port 68)"); err != nil {
		handle.Close()
		fmt.Println("Detecção de DHCP falso desativada (filtro BPF):", err)
		return
	}

	go func() {
		time.Sleep(60 * time.Second)
		dhcpMu.Lock()
		dhcpLearningPeriod = false
		total := len(knownDHCPServers)
		dhcpMu.Unlock()
		fmt.Printf("Detecção de DHCP falso: %d servidor(es) legítimo(s) identificado(s) na rede, monitorando por novos\n", total)
	}()

	go func() {
		defer handle.Close()
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range source.Packets() {
			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if dhcpLayer == nil {
				continue
			}
			dhcp, ok := dhcpLayer.(*layers.DHCPv4)
			if !ok {
				continue
			}
			if dhcp.Operation == layers.DHCPOpRequest {
				// client requests do not matter for rogue servers, but
				// they are how a device introduces itself — see
				// recordDHCPClient
				recordDHCPClient(dhcp)
				continue
			}

			var msgType layers.DHCPMsgType
			var offeredGateway, offeredDNS string
			for _, opt := range dhcp.Options {
				switch opt.Type {
				case layers.DHCPOptMessageType:
					if len(opt.Data) == 1 {
						msgType = layers.DHCPMsgType(opt.Data[0])
					}
				case layers.DHCPOptRouter:
					if len(opt.Data) >= 4 {
						offeredGateway = net.IP(opt.Data[:4]).String()
					}
				case layers.DHCPOptDNS:
					if len(opt.Data) >= 4 {
						offeredDNS = net.IP(opt.Data[:4]).String()
					}
				}
			}
			if msgType != layers.DHCPMsgTypeOffer && msgType != layers.DHCPMsgTypeAck {
				continue
			}

			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}
			server := networkLayer.NetworkFlow().Src().String()

			dhcpMu.Lock()
			if dhcpLearningPeriod {
				knownDHCPServers[server] = true
				dhcpMu.Unlock()
				continue
			}
			known := knownDHCPServers[server]
			if !known {
				knownDHCPServers[server] = true
			}
			dhcpMu.Unlock()

			if !known {
				offer := ""
				if offeredGateway != "" {
					offer += fmt.Sprintf(" Está entregando o gateway %s", offeredGateway)
					if offeredDNS != "" {
						offer += fmt.Sprintf(" e o DNS %s", offeredDNS)
					}
					offer += " — se esse gateway/DNS não for o do roteador legítimo, o tráfego de novos dispositivos está sendo desviado."
				}
				recordEvent("alerta_dhcp_falso", server, fmt.Sprintf(
					"Um servidor DHCP novo (%s) começou a responder na rede — pode ser um roteador antigo religado por engano, ou um ataque de DHCP falso (rogue DHCP) tentando sequestrar o tráfego de novos dispositivos.%s", server, offer))
			}
		}
	}()
}

// ---------- passive identification from DHCP requests ----------

// A device asking for an address says two useful things about itself in
// the broadcast it sends: the name it wants registered (option 12, e.g.
// "Galaxy-S21" or "ESP_3A2B1C") and a vendor class naming its DHCP
// client (option 60, e.g. "android-dhcp-14" or "MSFT 5.0"). Both arrive
// even from phones with a randomized MAC — the case where the vendor
// table has nothing to say. They are only seen when a device joins or
// reboots, since lease renewals go unicast to the router; what is learnt
// is kept for as long as the program runs.
type dhcpClient struct {
	Hostname    string
	VendorClass string
}

var dhcpClientsMu sync.RWMutex
var dhcpClients = map[string]dhcpClient{}

// maxDHCPClients caps the table: requests are broadcast by anyone, and a
// flood of forged ones with random MACs should not grow it without bound.
const maxDHCPClients = 4096

func recordDHCPClient(d *layers.DHCPv4) {
	if len(d.ClientHWAddr) != 6 {
		return
	}
	var c dhcpClient
	for _, opt := range d.Options {
		switch opt.Type {
		case layers.DHCPOptHostname:
			c.Hostname = cleanLabel(string(opt.Data), 64)
		case layers.DHCPOptClassID:
			c.VendorClass = cleanLabel(string(opt.Data), 64)
		}
	}
	if c.Hostname == "" && c.VendorClass == "" {
		return
	}
	mac := d.ClientHWAddr.String()
	dhcpClientsMu.Lock()
	defer dhcpClientsMu.Unlock()
	if _, known := dhcpClients[mac]; !known && len(dhcpClients) >= maxDHCPClients {
		return
	}
	dhcpClients[mac] = c
}

func dhcpClientFor(mac string) dhcpClient {
	if mac == "" {
		return dhcpClient{}
	}
	dhcpClientsMu.RLock()
	defer dhcpClientsMu.RUnlock()
	return dhcpClients[strings.ToLower(mac)]
}

// typeByDHCPVendorClass reads the client's own name. These are the
// strings the stock DHCP clients send; a device that customises them
// simply falls through to the other signals.
func typeByDHCPVendorClass(vc string) string {
	v := strings.ToLower(vc)
	switch {
	case v == "":
		return ""
	case strings.HasPrefix(v, "android-dhcp"):
		return "📱 Celular/tablet (Android)"
	case strings.HasPrefix(v, "msft"):
		return "💻 Computador (Windows)"
	case strings.HasPrefix(v, "udhcp"):
		// BusyBox's client: the default in embedded Linux firmware
		return "💡 Dispositivo embarcado (Linux/BusyBox)"
	}
	return ""
}
