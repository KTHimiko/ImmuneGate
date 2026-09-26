package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---------- CSV export ----------

// The dashboard shows the current state and the last events; the export
// is for keeping a record — attaching to a report, or opening in a
// spreadsheet to count things. Two choices follow from "a spreadsheet in
// Brazil": the separator is a semicolon, because Excel in pt-BR reads a
// comma as the decimal mark and would put each line in a single column,
// and the file starts with a UTF-8 BOM, without which Excel shows every
// accent as garbage.

func writeCSV(w http.ResponseWriter, filename string, header []string, rows func(write func([]string))) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	io.WriteString(w, "\xef\xbb\xbf") // UTF-8 BOM
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	cw.Write(header)
	rows(func(r []string) {
		for i := range r {
			r[i] = csvSafe(r[i])
		}
		cw.Write(r)
	})
	cw.Flush()
}

// csvSafe defuses formula injection. Hostnames, model names and page
// titles are chosen by whoever controls the device, and a spreadsheet
// runs a cell that starts with =, +, - or @ as a formula — a device named
// "=HYPERLINK(...)" would become a live link in the user's spreadsheet.
// A leading apostrophe makes the spreadsheet treat the cell as text.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "sim"
	}
	return "não"
}

func exportDevicesHandler(w http.ResponseWriter, r *http.Request) {
	results, _ := allResults()
	name := "dispositivos-" + time.Now().Format("2006-01-02-1504") + ".csv"
	writeCSV(w, name, []string{
		"IP", "IPv6", "MAC", "Fabricante", "Tipo provável", "Identificado por", "Modelo", "Nome",
		"Sistema provável", "Risco", "Portas abertas", "Isolado", "Pacotes bloqueados", "Confiável", "Agente",
	}, func(write func([]string)) {
		for _, d := range results {
			write([]string{
				d.IP, strings.Join(d.IPv6, " "), d.MAC, d.Vendor, d.ProbableType, d.IdentifiedBy, d.Model, d.Hostname,
				d.ProbableOS, d.Risk, strings.Join(d.PortNumbers, " "), yesNo(d.Isolated),
				fmt.Sprint(d.BlockedPackets), yesNo(d.Trusted), d.Agent,
			})
		}
	})
}

// exportHistoryHandler exports the whole history file, not the last
// events kept in memory for the dashboard: the export is the complete
// record. It streams line by line, so a long history is never loaded at
// once.
func exportHistoryHandler(w http.ResponseWriter, r *http.Request) {
	name := "historico-" + time.Now().Format("2006-01-02-1504") + ".csv"
	writeCSV(w, name, []string{"Quando", "Evento", "Tipo", "IP", "Detalhe"}, func(write func([]string)) {
		f, err := os.Open(historyFile)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var ev historyEvent
			if json.Unmarshal(sc.Bytes(), &ev) != nil {
				continue
			}
			label := eventLabel[ev.Type]
			if label == "" {
				label = ev.Type
			}
			write([]string{ev.When.Format("2006-01-02 15:04:05"), label, ev.Type, ev.IP, ev.Detail})
		}
	})
}
