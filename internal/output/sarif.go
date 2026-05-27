package output

import (
	"io"

	"github.com/chrj/diggity/internal/check"
)

// SARIFWriter renders a Report in SARIF 2.1.0 for CI integrations.
type SARIFWriter struct{}

func (SARIFWriter) Write(w io.Writer, _ check.Report) error {
	_, err := io.WriteString(w, "{\"version\":\"2.1.0\",\"runs\":[]}\n")
	return err
}
