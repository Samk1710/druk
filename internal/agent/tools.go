package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/samk/druk/internal/model"
)

// Define the tools that the LLM can call
var AvailableTools = []Tool{
	{
		Type: "function",
		Function: ToolFunction{
			Name:        "search_findings",
			Description: "Searches the generated security report for CVE findings matching a given package name or severity.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package_name": map[string]interface{}{
						"type":        "string",
						"description": "The name of the package to search for.",
					},
					"severity": map[string]interface{}{
						"type":        "string",
						"description": "The severity level (e.g. critical, high).",
					},
					"reachable_only": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, only return findings that are reachable from an entrypoint.",
					},
				},
			},
		},
	},
	{
		Type: "function",
		Function: ToolFunction{
			Name:        "get_call_path",
			Description: "Returns the reachability call path for a specific finding ID.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{
						"type":        "string",
						"description": "The CVE ID or finding ID to get the call path for.",
					},
				},
				"required": []string{"finding_id"},
			},
		},
	},
	{
		Type: "function",
		Function: ToolFunction{
			Name:        "get_supply_chain_score",
			Description: "Returns the OpenSSF scorecard breakdown and deductions.",
			Parameters: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	},
}

// ExecuteTool takes a tool call and runs the corresponding local Go function against the Report.
func ExecuteTool(report *model.Report, call ToolCall) (string, error) {
	switch call.Function.Name {
	case "search_findings":
		var args struct {
			PackageName   string `json:"package_name"`
			Severity      string `json:"severity"`
			ReachableOnly bool   `json:"reachable_only"`
		}
		if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
			return "", err
		}
		var results []model.Finding
		for _, f := range report.Findings {
			if args.PackageName != "" && !strings.Contains(strings.ToLower(f.Package), strings.ToLower(args.PackageName)) {
				continue
			}
			if args.Severity != "" && !strings.Contains(strings.ToLower(f.Severity), strings.ToLower(args.Severity)) {
				continue
			}
			if args.ReachableOnly && f.Reachability != "reachable" {
				continue
			}
			results = append(results, f)
		}
		if len(results) == 0 {
			return "No matching findings found.", nil
		}
		b, _ := json.Marshal(results)
		return string(b), nil

	case "get_call_path":
		var args struct {
			FindingID string `json:"finding_id"`
		}
		if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
			return "", err
		}
		for _, f := range report.Findings {
			if strings.EqualFold(f.ID, args.FindingID) {
				if len(f.CallPath) == 0 {
					return "No call path available for this finding.", nil
				}
				return strings.Join(f.CallPath, " -> "), nil
			}
		}
		return "Finding not found.", nil

	case "get_supply_chain_score":
		if !report.SupplyChain.IsScorecard {
			return "OpenSSF Scorecard data unavailable.", nil
		}
		return fmt.Sprintf("Score: %.1f/10. Checks: %+v", report.SupplyChain.Score, report.SupplyChain.Checks), nil

	default:
		return "", fmt.Errorf("unknown tool %s", call.Function.Name)
	}
}
