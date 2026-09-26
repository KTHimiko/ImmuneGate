package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSVSafe(t *testing.T) {
	cases := map[string]string{
		`=HYPERLINK("http://x","clique")`: `'=HYPERLINK("http://x","clique")`,
		"+55 11":                          "'+55 11",
		"-1":                              "'-1",
		"@SUM(A1)":                        "'@SUM(A1)",
		"TV do quarto":                    "TV do quarto",
		"192.168.0.5":                     "192.168.0.5",
		"":                                "",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, queria %q", in, got, want)
		}
	}
}

func TestWriteCSVForBrazilianSpreadsheets(t *testing.T) {
	rec := httptest.NewRecorder()
	writeCSV(rec, "x.csv", []string{"Nome", "Risco"}, func(write func([]string)) {
		write([]string{"=cmd", "médio"})
	})
	body := rec.Body.String()
	if !strings.HasPrefix(body, "\xef\xbb\xbf") {
		t.Error("sem BOM o Excel mostra os acentos quebrados")
	}
	if !strings.Contains(body, "Nome;Risco\n") || !strings.Contains(body, "'=cmd;médio\n") {
		t.Errorf("conteúdo inesperado: %q", body)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition %q", cd)
	}
}
