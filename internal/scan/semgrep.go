package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/samk/druk/internal/model"
)

type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
}

func RunSemgrep(target string) ([]model.SASTFinding, error) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		return nil, fmt.Errorf("semgrep binary not found (skipping SAST)")
	}

	cmd := exec.Command("semgrep", "scan", "--config", "auto", "--json", target)
	cmd.Env = append(os.Environ(), "SEMGREP_SEND_METRICS=off")
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	// Semgrep returns non-zero exit code if it finds issues, so we ignore the error return
	// as long as we get valid JSON out of it.
	_ = cmd.Run()

	if outBuf.Len() == 0 {
		return nil, fmt.Errorf("semgrep returned empty output")
	}

	var output semgrepOutput
	if err := json.Unmarshal(outBuf.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep json: %w", err)
	}

	var findings []model.SASTFinding
	for _, res := range output.Results {
		findings = append(findings, model.SASTFinding{
			ID:       res.CheckID,
			Message:  res.Extra.Message,
			Severity: res.Extra.Severity,
			Path:     res.Path,
			Line:     res.Start.Line,
		})
	}

	return findings, nil
}
