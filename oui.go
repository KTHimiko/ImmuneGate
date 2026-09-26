package main

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// ---------- IEEE vendor registry ----------

// The hand-written ouiTable covers about seventy prefixes, so on a real
// network most devices came out as "Desconhecido". The IEEE publishes the
// whole registry — tens of thousands of blocks — and most Linux systems
// already carry a copy for lspci/lsusb (hwdata) or for nmap/Wireshark.
// Reading it from disk keeps the binary small and the list as current as
// the system's package manager keeps it; when none is installed the
// program falls back to ouiTable alone, as before.
var ouiRegistryPaths = []string{
	"/usr/share/hwdata/oui.txt",         // Arch, Fedora (hwdata)
	"/usr/share/ieee-data/oui.txt",      // Debian, Ubuntu (ieee-data)
	"/var/lib/ieee-data/oui.txt",        // older Debian
	"/usr/share/misc/oui.txt",           // some distributions
	"/usr/share/nmap/nmap-mac-prefixes", // nmap, different format
}

// ouiRegistry maps the prefix as six uppercase hex digits ("286FB9") to the
// organisation name. Written once at startup, read-only afterwards.
var ouiRegistry = map[string]string{}

func loadOUIRegistry() (path string, entries int) {
	for _, p := range ouiRegistryPaths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		reg := parseOUIRegistry(f)
		f.Close()
		if len(reg) > 0 {
			ouiRegistry = reg
			return p, len(reg)
		}
	}
	return "", 0
}

// parseOUIRegistry reads both formats in circulation: the IEEE text file
//
//	28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd.
//
// and nmap's prefix list
//
//	286FB9 Nokia Shanghai Bell
//
// Anything else (the IEEE file's address lines, comments) is skipped.
func parseOUIRegistry(r io.Reader) map[string]string {
	reg := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		var prefix, org string
		if i := strings.Index(line, "(hex)"); i > 0 {
			prefix = strings.ReplaceAll(strings.TrimSpace(line[:i]), "-", "")
			org = strings.TrimSpace(line[i+len("(hex)"):])
		} else if len(line) > 7 && line[6] == ' ' {
			prefix, org = line[:6], strings.TrimSpace(line[7:])
			// the IEEE file repeats every entry as "286FB9 (base 16) ...",
			// which has the nmap shape and would overwrite the clean name
			if strings.HasPrefix(org, "(") {
				continue
			}
		}
		if len(prefix) != 6 || org == "" || !isHex(prefix) {
			continue
		}
		reg[strings.ToUpper(prefix)] = org
	}
	return reg
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// vendorTypeHints turns a registry organisation name into a device type,
// but only for vendors that make essentially one kind of product. Samsung,
// Xiaomi, Huawei, LG, Sony, TP-Link or Intelbras make phones and TVs and
// routers and cameras alike, so for them the vendor is shown and the type
// is left for a stronger signal to decide.
var vendorTypeHints = []struct{ marker, deviceType string }{
	{"espressif", typeIoT},
	{"tuya", typeIoT},
	{"shelly", typeIoT},
	{"allterco", typeIoT}, // maker of Shelly
	{"itead", typeIoT},    // maker of Sonoff
	{"signify", typeIoT},
	{"philips lighting", typeIoT},
	{"nest labs", typeIoT},
	{"hikvision", typeCamera},
	{"dahua", typeCamera},
	{"axis communications", typeCamera},
	{"reolink", typeCamera},
	{"ezviz", typeCamera},
	{"seiko epson", typePrinter},
	{"brother industries", typePrinter},
	{"lexmark", typePrinter},
	{"xerox", typePrinter},
	{"kyocera", typePrinter},
	{"ricoh", typePrinter},
	{"ubiquiti", typeNetwork},
	{"mikrotik", typeNetwork},
	{"routerboard", typeNetwork},
	{"cisco", typeNetwork},
	{"aruba", typeNetwork},
	{"ruckus", typeNetwork},
	{"arcadyan", typeNetwork}, // ISP-supplied modems
	{"sagemcom", typeNetwork}, // idem
	{"askey", typeNetwork},    // idem
	{"technicolor", typeNetwork},
	{"arris", typeNetwork},
	{"fiberhome", typeNetwork}, // fibre ONTs, common in Brazil
	{"nintendo", typeConsole},
	{"sony interactive", typeConsole},
	{"raspberry pi", "🍓 Raspberry Pi / placa de projeto"},
	{"roku", typeStreaming},
	{"sonos", typeStreaming},
	{"amazon technologies", typeStreaming},
	{"synology", typeNAS},
	{"qnap", typeNAS},
	{"positivo", typePC}, // Brazilian PC maker
	{"vmware", "🖥️ Máquina virtual"},
	{"oracle", "🖥️ Máquina virtual"}, // VirtualBox's 08:00:27
}

func vendorTypeHint(org string) string {
	o := strings.ToLower(org)
	for _, h := range vendorTypeHints {
		if strings.Contains(o, h.marker) {
			return h.deviceType
		}
	}
	return ""
}
