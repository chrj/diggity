package output

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/chrj/diggity/internal/check"
)

func sampleReport() check.Report {
	return check.Report{
		Results: []check.Result{
			{
				Check:    "delegation",
				Hostname: "example.com",
				Status:   check.StatusPass,
				Findings: []check.Finding{{Status: check.StatusPass, Message: "ok"}},
			},
			{
				Check:    "dnssec",
				Hostname: "example.com",
				Status:   check.StatusFail,
				Findings: []check.Finding{{
					Status:  check.StatusFail,
					Message: "signature invalid",
					Detail:  "line 1\nline 2\n",
				}},
			},
		},
		Summary: check.Summary{Pass: 1, Fail: 1},
	}
}

func TestNewReturnsExpectedWriter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format string
		want   any
	}{
		{"", &TextWriter{}},
		{"text", &TextWriter{}},
		{"json", &JSONWriter{}},
		{"ndjson", &NDJSONWriter{}},
		{"sarif", &SARIFWriter{}},
	}

	for _, tt := range tests {
		got, err := New(tt.format)
		if err != nil {
			t.Fatalf("New(%q) error = %v", tt.format, err)
		}
		if gotType, wantType := reflect.TypeOf(got).String(), reflect.TypeOf(tt.want).String(); gotType != wantType {
			t.Fatalf("New(%q) type = %s, want %s", tt.format, gotType, wantType)
		}
	}

	if _, err := New("yaml"); err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Fatalf("New(%q) error = %v, want unknown format error", "yaml", err)
	}
}

func TestTextWriterLabelAndSummarise(t *testing.T) {
	t.Parallel()

	if got := summarise(check.Result{
		Findings: []check.Finding{
			{Status: check.StatusPass},
			{Status: check.StatusWarn},
			{Status: check.StatusWarn},
			{Status: check.StatusSkip},
		},
	}); got != "1 pass, 2 warn, 1 skip" {
		t.Fatalf("summarise() = %q", got)
	}

	if got := (TextWriter{NoColor: true}).label(check.StatusWarn); got != "[WARN]" {
		t.Fatalf("label() = %q, want %q", got, "[WARN]")
	}
	if got := (TextWriter{}).label(check.StatusFail); !strings.Contains(got, "[FAIL]") {
		t.Fatalf("colored label missing FAIL marker: %q", got)
	}
}

func TestTextWriterWriteQuietFiltersPassingResults(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := (TextWriter{NoColor: true, Quiet: true}).Write(&buf, sampleReport())
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "example.com") {
		t.Fatalf("Write() output missing hostname: %q", out)
	}
	if strings.Contains(out, "delegation") {
		t.Fatalf("Write() output unexpectedly included passing result: %q", out)
	}
	if !strings.Contains(out, "[FAIL]  dnssec") || !strings.Contains(out, "signature invalid") {
		t.Fatalf("Write() output missing failing result details: %q", out)
	}
	if !strings.Contains(out, "line 1\n             line 2") {
		t.Fatalf("Write() output missing indented detail lines: %q", out)
	}
	if !strings.Contains(out, "summary: 1 pass, 0 warn, 1 fail, 0 skip") {
		t.Fatalf("Write() output missing summary: %q", out)
	}
}

func TestStructuredWriters(t *testing.T) {
	t.Parallel()

	report := sampleReport()

	var jsonBuf bytes.Buffer
	if err := (JSONWriter{}).Write(&jsonBuf, report); err != nil {
		t.Fatalf("JSONWriter.Write() error = %v", err)
	}
	jsonOut := jsonBuf.String()
	if !strings.Contains(jsonOut, "\"results\"") || !strings.Contains(jsonOut, "\"summary\"") {
		t.Fatalf("JSON output missing expected keys: %q", jsonOut)
	}

	var ndjsonBuf bytes.Buffer
	if err := (NDJSONWriter{}).Write(&ndjsonBuf, report); err != nil {
		t.Fatalf("NDJSONWriter.Write() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(ndjsonBuf.String()), "\n")
	if len(lines) != len(report.Results) {
		t.Fatalf("NDJSON lines = %d, want %d", len(lines), len(report.Results))
	}
	if !strings.Contains(lines[0], "\"check\":\"delegation\"") || !strings.Contains(lines[1], "\"check\":\"dnssec\"") {
		t.Fatalf("NDJSON output missing encoded results: %q", ndjsonBuf.String())
	}

	var sarifBuf bytes.Buffer
	if err := (SARIFWriter{}).Write(&sarifBuf, report); err != nil {
		t.Fatalf("SARIFWriter.Write() error = %v", err)
	}
	if got, want := sarifBuf.String(), "{\"version\":\"2.1.0\",\"runs\":[]}\n"; got != want {
		t.Fatalf("SARIF output = %q, want %q", got, want)
	}
}
