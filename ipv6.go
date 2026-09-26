package main

import (
	"net"
	"os/exec"
	"sort"
	"strings"
)

// ---------- IPv6 neighbour discovery ----------

// The scan finds devices by pinging every IPv4 address in the range and
// reading the ARP table. IPv6 has no ARP, but it has something better for
// discovery: one echo request to ff02::1, the all-nodes multicast group,
// and every IPv6 host on the link is expected to answer. The replies fill
// the kernel's neighbour table with address → MAC pairs, which is read
// back the same way /proc/net/arp is.
//
// Two things come out of it. Devices already known by IPv4 get their IPv6
// addresses on the card — worth seeing, since traffic over IPv6 does not
// go through the IPv4 rules. And a device that answered only over IPv6
// shows up at all, instead of being invisible.

// discoverIPv6Neighbours returns, per MAC (lowercase, as
// net.HardwareAddr.String prints it), the IPv6 addresses seen for it.
func discoverIPv6Neighbours(iface string) map[string][]string {
	// the output does not matter, only the side effect on the neighbour
	// table; an error just means nothing answered or IPv6 is off
	exec.Command("ping", "-6", "-c", "2", "-W", "1", "-I", iface, "ff02::1").Run()

	out, err := exec.Command("ip", "-6", "neigh", "show", "dev", iface).Output()
	if err != nil {
		return nil
	}
	return parseIPv6Neighbours(string(out))
}

// parseIPv6Neighbours reads `ip -6 neigh show dev X`, whose lines look like
//
//	fe80::1a2b:3cff:fe4d:5e6f lladdr 1a:2b:3c:4d:5e:6f router REACHABLE
//	2804:14c::1234 lladdr 1a:2b:3c:4d:5e:6f STALE
//	fe80::99 FAILED
//
// Entries with no link-layer address (FAILED, INCOMPLETE) never answered
// and are skipped, as are multicast addresses.
func parseIPv6Neighbours(output string) map[string][]string {
	byMAC := map[string][]string{}
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() != nil || ip.IsMulticast() {
			continue
		}
		var mac net.HardwareAddr
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				mac, _ = net.ParseMAC(f[i+1])
			}
		}
		if mac == nil {
			continue
		}
		byMAC[mac.String()] = append(byMAC[mac.String()], ip.String())
	}
	for mac := range byMAC {
		sortIPv6(byMAC[mac])
	}
	return byMAC
}

// sortIPv6 puts the link-local address first. It is the one to name an
// IPv6-only device by: global addresses include temporary privacy
// addresses that rotate every few hours, and naming the device by one of
// them would make it look like a new device each time it changes.
func sortIPv6(addrs []string) {
	sort.SliceStable(addrs, func(i, j int) bool {
		li := strings.HasPrefix(addrs[i], "fe80:")
		lj := strings.HasPrefix(addrs[j], "fe80:")
		if li != lj {
			return li
		}
		return addrs[i] < addrs[j]
	})
}

// shortIPv6 abbreviates an address for the map, where a full IPv6
// address does not fit under a node: the last group is what tells
// neighbours apart.
func shortIPv6(ip string) string {
	if i := strings.LastIndex(ip, ":"); i >= 0 && i < len(ip)-1 {
		return "…:" + ip[i+1:]
	}
	return ip
}
