package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/samk/druk/internal/model"
)

// SARIF outputs the report findings as a SARIF document.
func SARIF(w io.Writer, report *model.Report) error {
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":            "Druk",
						"informationUri":  "https://github.com/samk/druk",
						"version":         "1.0.0",
						"rules":           buildRules(report),
					},
				},
				"results": buildResults(report),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

func buildRules(report *model.Report) []map[string]interface{} {
	var rules []map[string]interface{}
	seen := make(map[string]bool)

	for _, f := range report.Findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			rules = append(rules, map[string]interface{}{
				"id": f.ID,
				"shortDescription": map[string]interface{}{
					"text": fmt.Sprintf("Vulnerability %s in %s", f.ID, f.Package),
				},
			})
		}
	}
	return rules
}

func buildResults(report *model.Report) []map[string]interface{} {
	var results []map[string]interface{}

	for _, f := range report.Findings {
		msg := fmt.Sprintf("Found %s in %s (version %s).", f.ID, f.Package, f.Version)
		if f.Reachability == "reachable" {
			msg += " (REACHABLE)"
		}

		// Pick the first file in the call path as the physical location if available.
		var uri string = "dependency"
		if len(f.CallPath) > 0 {
			parts := strings.Split(f.CallPath[0], ":")
			if len(parts) > 0 {
				uri = parts[0]
			}
		}

		res := map[string]interface{}{
			"ruleId": f.ID,
			"level":  mapSeverityToSARIF(f.Severity),
			"message": map[string]interface{}{
				"text": msg,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": uri,
						},
						"region": map[string]interface{}{
							"startLine": 1,
						},
					},
				},
			},
		}
		results = append(results, res)
	}

	return results
}

func mapSeverityToSARIF(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
