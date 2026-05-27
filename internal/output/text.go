package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/chrj/diggity/internal/check"
)

// TextWriter renders a Report as human-readable text grouped per hostname.
type TextWriter struct {
	NoColor bool
	Quiet   bool
}

func (t TextWriter) Write(w io.Writer, report check.Report) error {
	byHost := map[string][]check.Result{}
	var order []string
	for _, r := range report.Results {
		if _, seen := byHost[r.Hostname]; !seen {
			order = append(order, r.Hostname)
		}
		byHost[r.Hostname] = append(byHost[r.Hostname], r)
	}

	for i, host := range order {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, host)
		for _, res := range byHost[host] {
			if t.Quiet && res.Status != check.StatusFail {
				continue
			}
			label := t.label(res.Status)
			fmt.Fprintf(w, "  %s  %-11s  %s\n", label, res.Check, summarise(res))
			for _, f := range res.Findings {
				if f.Status == check.StatusPass && len(res.Findings) == 1 {
					continue
				}
				if t.Quiet && f.Status != check.StatusFail {
					continue
				}
				glyph := t.label(f.Status)
				fmt.Fprintf(w, "         %s  %s\n", glyph, f.Message)
				if f.Detail != "" {
					for _, line := range strings.Split(strings.TrimRight(f.Detail, "\n"), "\n") {
						fmt.Fprintf(w, "             %s\n", line)
					}
				}
			}
		}
	}

	if len(order) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "summary: %d pass, %d warn, %d fail, %d skip\n",
		report.Summary.Pass, report.Summary.Warn, report.Summary.Fail, report.Summary.Skip)
	return nil
}

func summarise(res check.Result) string {
	if len(res.Findings) == 1 {
		return res.Findings[0].Message
	}
	var pass, warn, fail, skip int
	for _, f := range res.Findings {
		switch f.Status {
		case check.StatusPass:
			pass++
		case check.StatusWarn:
			warn++
		case check.StatusFail:
			fail++
		case check.StatusSkip:
			skip++
		}
	}
	parts := []string{}
	if pass > 0 {
		parts = append(parts, fmt.Sprintf("%d pass", pass))
	}
	if warn > 0 {
		parts = append(parts, fmt.Sprintf("%d warn", warn))
	}
	if fail > 0 {
		parts = append(parts, fmt.Sprintf("%d fail", fail))
	}
	if skip > 0 {
		parts = append(parts, fmt.Sprintf("%d skip", skip))
	}
	return strings.Join(parts, ", ")
}

func (t TextWriter) label(s check.Status) string {
	text := strings.ToUpper(s.String())
	if t.NoColor {
		return fmt.Sprintf("[%s]", text)
	}
	var code string
	switch s {
	case check.StatusPass:
		code = "32"
	case check.StatusWarn:
		code = "33"
	case check.StatusFail:
		code = "31"
	case check.StatusSkip:
		code = "90"
	default:
		return fmt.Sprintf("[%s]", text)
	}
	return fmt.Sprintf("\x1b[%sm[%s]\x1b[0m", code, text)
}
