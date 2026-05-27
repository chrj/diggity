package output

import (
	"encoding/json"
	"io"

	"github.com/chrj/diggity/internal/check"
)

// JSONWriter renders a Report as a single pretty-printed JSON object.
type JSONWriter struct{}

func (JSONWriter) Write(w io.Writer, report check.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
