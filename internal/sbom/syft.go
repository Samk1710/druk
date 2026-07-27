package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/samk/druk/internal/cache"
	"github.com/samk/druk/internal/model"
)

type cyclonedxJSON struct {
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"components"`
}

// Generate runs syft to generate a CycloneDX JSON SBOM and parses it into our internal model.
func Generate(target string) ([]model.Component, error) {
	// 1. Check Cache
	cacheDir, err := cache.GetCacheDir()
	if err == nil {
		repoHash, err := cache.ComputeHash(target)
		if err == nil {
			cacheFile := filepath.Join(cacheDir, repoHash, "sbom.json")
			if data, err := os.ReadFile(cacheFile); err == nil {
				var cachedComponents []model.Component
				if err := json.Unmarshal(data, &cachedComponents); err == nil {
					return cachedComponents, nil
				}
			}
		}
	}

	if _, err := exec.LookPath("syft"); err != nil {
		return nil, fmt.Errorf("syft binary not found in PATH: %w", err)
	}

	cmd := exec.Command("syft", "dir:"+target, "-o", "cyclonedx-json", "-q") // -q for quiet to avoid stderr noise
	cmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false")
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
			Purl:    c.Purl,
		})
	}

	// 2. Write Cache
	if cacheDir != "" {
		if repoHash, err := cache.ComputeHash(target); err == nil {
			cDir := filepath.Join(cacheDir, repoHash)
			os.MkdirAll(cDir, 0755)
			if cacheData, err := json.Marshal(components); err == nil {
				os.WriteFile(filepath.Join(cDir, "sbom.json"), cacheData, 0644)
			}
		}
	}

	return components, nil
}
