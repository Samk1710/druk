package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/samk/druk/internal/model"
)

type gitleaksOutput []struct {
	Description string `json:"Description"`
	RuleID      string `json:"RuleID"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
}

func RunGitleaks(target string) ([]model.SecretFinding, error) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		return nil, fmt.Errorf("gitleaks binary not found (skipping secrets)")
	}

	tmpReport := filepath.Join(os.TempDir(), "druk-gitleaks.json")
	defer os.Remove(tmpReport)

	cmd := exec.Command("gitleaks", "detect", "--no-git", "--source", target, "--report-format", "json", "--report-path", tmpReport)

	// gitleaks returns non-zero if leaks are found
	_ = cmd.Run()

	b, err := os.ReadFile(tmpReport)
	if err != nil {
		// If file doesn't exist, gitleaks might have failed or found nothing.
		return nil, nil
	}

	var raw gitleaksOutput
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks json: %w", err)
	}

	var findings []model.SecretFinding
	for _, leak := range raw {
		findings = append(findings, model.SecretFinding{
			RuleID:      leak.RuleID,
			Description: leak.Description,
			Severity:    "CRITICAL", // Gitleaks findings are generally critical
			Path:        leak.File,
			Line:        leak.StartLine,
		})
	}

	return findings, nil
}
