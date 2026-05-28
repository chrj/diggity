package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/chrj/diggity/internal/check"
)

// TextWriter renders a Report as human-readable text grouped per hostname.
//
// Color toggles ANSI styling. Unicode toggles the tree-style layout with
// status glyphs; when off, the renderer falls back to the [PASS]/[WARN]
// bracket format that older terminals and piped consumers can handle.
type TextWriter struct {
	Color   bool
	Unicode bool
	Quiet   bool
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiGrey   = "\x1b[90m"
)

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
		if t.Unicode {
			t.renderHostTree(w, host, byHost[host])
		} else {
			t.renderHostBracket(w, host, byHost[host])
		}
	}

	if len(order) > 0 {
		fmt.Fprintln(w)
	}
	t.renderSummary(w, report.Summary)
	return nil
}

func (t TextWriter) renderHostBracket(w io.Writer, host string, results []check.Result) {
	fmt.Fprintln(w, t.style(host, ansiBold))
	for _, res := range results {
		if t.Quiet && res.Status != check.StatusFail {
			continue
		}
		fmt.Fprintf(w, "  %s  %-11s  %s\n", t.label(res.Status), res.Check, summarise(res))
		for _, f := range res.Findings {
			if f.Status == check.StatusPass && len(res.Findings) == 1 {
				continue
			}
			if t.Quiet && f.Status != check.StatusFail {
				continue
			}
			fmt.Fprintf(w, "         %s  %s\n", t.label(f.Status), f.Message)
			if f.Detail != "" {
				for line := range strings.SplitSeq(strings.TrimRight(f.Detail, "\n"), "\n") {
					fmt.Fprintf(w, "             %s\n", t.style(line, ansiDim))
				}
			}
		}
	}
}

func (t TextWriter) renderHostTree(w io.Writer, host string, results []check.Result) {
	visible := make([]check.Result, 0, len(results))
	for _, res := range results {
		if t.Quiet && res.Status != check.StatusFail {
			continue
		}
		visible = append(visible, res)
	}
	fmt.Fprintln(w, t.style(host, ansiBold))
	for i, res := range visible {
		last := i == len(visible)-1
		branch := "├─"
		cont := "│  "
		if last {
			branch = "└─"
			cont = "   "
		}
		fmt.Fprintf(w, "%s %s %-11s  %s\n",
			branch, t.glyph(res.Status), res.Check, summarise(res))

		findings := t.visibleFindings(res)
		for _, f := range findings {
			fmt.Fprintf(w, "%s   %s %s\n", cont, t.glyph(f.Status), f.Message)
			if f.Detail != "" {
				for line := range strings.SplitSeq(strings.TrimRight(f.Detail, "\n"), "\n") {
					fmt.Fprintf(w, "%s     %s\n", cont, t.style(line, ansiDim))
				}
			}
		}
	}
}

// visibleFindings filters the findings of a result the same way the bracket
// renderer does: a single passing finding is implicit in the parent line,
// and quiet mode drops anything that isn't a failure.
func (t TextWriter) visibleFindings(res check.Result) []check.Finding {
	out := make([]check.Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		if f.Status == check.StatusPass && len(res.Findings) == 1 {
			continue
		}
		if t.Quiet && f.Status != check.StatusFail {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (t TextWriter) renderSummary(w io.Writer, s check.Summary) {
	if !t.Unicode {
		fmt.Fprintf(w, "summary: %d pass, %d warn, %d fail, %d skip\n",
			s.Pass, s.Warn, s.Fail, s.Skip)
		return
	}
	parts := []string{
		fmt.Sprintf("%d %s", s.Pass, t.glyph(check.StatusPass)),
		fmt.Sprintf("%d %s", s.Warn, t.glyph(check.StatusWarn)),
		fmt.Sprintf("%d %s", s.Fail, t.glyph(check.StatusFail)),
		fmt.Sprintf("%d %s", s.Skip, t.glyph(check.StatusSkip)),
	}
	fmt.Fprintln(w, strings.Join(parts, t.style(" · ", ansiDim)))
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
	text := fmt.Sprintf("[%s]", strings.ToUpper(s.String()))
	return t.style(text, statusColor(s))
}

func (t TextWriter) glyph(s check.Status) string {
	var g string
	switch s {
	case check.StatusPass:
		g = "✓"
	case check.StatusWarn:
		g = "⚠"
	case check.StatusFail:
		g = "✗"
	case check.StatusSkip:
		g = "⊘"
	default:
		g = "?"
	}
	return t.style(g, statusColor(s))
}

func statusColor(s check.Status) string {
	switch s {
	case check.StatusPass:
		return ansiGreen
	case check.StatusWarn:
		return ansiYellow
	case check.StatusFail:
		return ansiRed
	case check.StatusSkip:
		return ansiGrey
	}
	return ""
}

func (t TextWriter) style(s, code string) string {
	if !t.Color || code == "" {
		return s
	}
	return code + s + ansiReset
}
