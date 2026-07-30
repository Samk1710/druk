package agent

import (
	"encoding/json"
	"fmt"

	"github.com/samk/druk/internal/model"
)

const synthesizerSystemPrompt = `You are an elite Application Security Engineer analyzing a security scanner report.
Your job is to read the provided structured JSON report (which contains CVEs, SAST findings, Secrets, Reachability graphs, Supply Chain scores, and a Threat Model) and synthesize it into a highly actionable, executive-level summary.

CRITICAL RULES:
1. DO NOT HALLUCINATE. Only mention findings that actually exist in the JSON.
2. PRIORITIZE REACHABILITY. If a CVE is marked as "reachable", emphasize it heavily. If it is "unreachable", note that it is low priority.
3. Be concise. The output will be displayed in a terminal CLI.

You MUST output your response in the following JSON format:
{
	"summary": "A 3-5 sentence executive summary of the overall security posture.",
	"prioritized_actions": [
		"Action 1 (e.g. Upgrade package X immediately because CVE-Y is reachable)",
		"Action 2",
		"Action 3"
	]
}`

// Synthesize consumes the full report and generates an AI narrative summary.
// If the LLM client fails or is not configured, it silently returns an empty narrative.
func Synthesize(report *model.Report) model.AINarrative {
	// Fallback function for deterministic rule-based summary
	fallback := func() model.AINarrative {
		summary := fmt.Sprintf("Druk analyzed %d dependencies and found %d vulnerabilities. ", len(report.SBOM.Components), len(report.Findings))
		var reachable int
		for _, f := range report.Findings {
			if f.Reachability == "reachable" {
				reachable++
			}
		}
		if reachable > 0 {
			summary += fmt.Sprintf("CRITICAL: %d vulnerabilities are highly reachable from entrypoints.", reachable)
		} else {
			summary += "No reachable CVEs were detected."
		}

		return model.AINarrative{
			Summary: summary,
			PrioritizedActions: []string{
				"Review reachable vulnerabilities first.",
				"Check Supply Chain score for architectural gaps.",
			},
			ModelUsed: "Rule-based Fallback",
		}
	}

	client, err := NewClient()
	if err != nil {
		return fallback() // Graceful degradation if no API key
	}

	// 1. COMPRESS THE REPORT (Drop SBOM, Keep top 15 findings)
	type compressedReport struct {
		Findings      []model.Finding       `json:"findings"`
		SAST          []model.SASTFinding   `json:"sast"`
		Secrets       []model.SecretFinding `json:"secrets"`
		AttackSurface model.AttackSurface   `json:"attackSurface"`
		SupplyChain   model.SupplyChain     `json:"supplyChain"`
		ThreatModel   model.ThreatModel     `json:"threatModel"`
	}

	// Sort findings by severity/reachability (naively for now: just grab first 15)
	// In a real implementation, we'd sort by Reachable=true first.
	var topFindings []model.Finding
	reachableCount := 0
	for _, f := range report.Findings {
		if f.Reachability == "reachable" {
			topFindings = append(topFindings, f)
			reachableCount++
		}
	}
	for _, f := range report.Findings {
		if len(topFindings) >= 15 {
			break
		}
		if f.Reachability != "reachable" {
			topFindings = append(topFindings, f)
		}
	}

	comp := compressedReport{
		Findings:      topFindings,
		SAST:          report.SAST,
		Secrets:       report.Secrets,
		AttackSurface: report.AttackSurface,
		SupplyChain:   report.SupplyChain,
		ThreatModel:   report.ThreatModel,
	}

	reportData, err := json.Marshal(comp)
	if err != nil {
		return fallback()
	}

	// 2. RETRY LOOP WITH SCHEMA VALIDATION
	for attempts := 0; attempts < 2; attempts++ {
		responseStr, err := client.Generate(synthesizerSystemPrompt, string(reportData))
		if err != nil {
			continue // Retry on network/API failure
		}

		var narrative model.AINarrative
		if err := json.Unmarshal([]byte(responseStr), &narrative); err == nil {
			if narrative.Summary != "" && len(narrative.PrioritizedActions) > 0 {
				narrative.ModelUsed = client.Model
				return narrative
			}
		}
	}

	// 3. FALLBACK IF LLM FAILS
	return fallback()
}
