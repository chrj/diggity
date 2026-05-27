package output

import (
	"fmt"
	"io"

	"github.com/chrj/diggity/internal/check"
)

// Writer renders a Report to an output stream.
type Writer interface {
	Write(w io.Writer, report check.Report) error
}

// New returns the Writer registered for the named format.
func New(format string) (Writer, error) {
	switch format {
	case "", "text":
		return &TextWriter{}, nil
	case "json":
		return &JSONWriter{}, nil
	case "ndjson":
		return &NDJSONWriter{}, nil
	case "sarif":
		return &SARIFWriter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %q", format)
	}
}
