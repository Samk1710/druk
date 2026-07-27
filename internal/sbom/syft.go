package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/samk/druk/internal/model"
)

type cyclonedxJSON struct {
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"components"`
}

// Generate runs syft to generate a CycloneDX JSON SBOM and parses it into our internal model.
func Generate(target string) ([]model.Component, error) {
	if _, err := exec.LookPath("syft"); err != nil {
		return nil, fmt.Errorf("syft binary not found in PATH: %w", err)
	}

	cmd := exec.Command("syft", "dir:"+target, "-o", "cyclonedx-json", "-q") // -q for quiet to avoid stderr noise
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft execution failed: %v, stderr: %s", err, errBuf.String())
	}

	var raw cyclonedxJSON
	if err := json.Unmarshal(outBuf.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse syft output: %w", err)
	}

	components := make([]model.Component, 0, len(raw.Components))
	for _, c := range raw.Components {
		components = append(components, model.Component{
			Name:    c.Name,
			Version: c.Version,
		})
	}

	return components, nil
}
