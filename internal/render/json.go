package render

import (
	"encoding/json"
	"io"

	"github.com/samk/druk/internal/model"
)

// JSON outputs the report as raw JSON to the given writer.
func JSON(w io.Writer, report *model.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
