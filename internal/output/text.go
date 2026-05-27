package output

import (
	"io"

	"github.com/chrj/diggity/internal/check"
)

// TextWriter renders a Report as human-readable text grouped per hostname.
type TextWriter struct {
	NoColor bool
	Quiet   bool
}

func (TextWriter) Write(w io.Writer, _ check.Report) error {
	_, err := io.WriteString(w, "text output not implemented yet\n")
	return err
}
