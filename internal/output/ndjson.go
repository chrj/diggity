package output

import (
	"encoding/json"
	"io"

	"github.com/chrj/diggity/internal/check"
)

// NDJSONWriter renders one Result per line, suitable for log pipelines.
type NDJSONWriter struct{}

func (NDJSONWriter) Write(w io.Writer, report check.Report) error {
	enc := json.NewEncoder(w)
	for _, r := range report.Results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
