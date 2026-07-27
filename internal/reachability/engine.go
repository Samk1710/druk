package reachability

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/samk/druk/internal/model"
)

// Analyze updates the findings in the report with their reachability status.
func Analyze(report *model.Report, cpgPath string) error {
	for i := range report.Findings {
		finding := &report.Findings[i]

		// 1. Identify Target Symbol
		// Since extracting the exact vulnerable method from OSV/VC can be complex,
		// our Phase 3 baseline fallback is to check if the vulnerable *package* itself is reachable or imported.
		targetRegex := fmt.Sprintf(".*%s.*", finding.Package)

		// 2. Query Atom for paths from any entrypoint to the target
		// We use the algorithms command with type paths
		cmd := exec.Command("atom", "algorithms", "--type", "paths", "--target", targetRegex, cpgPath)
		output, err := cmd.CombinedOutput()
		
		if err != nil {
			// If it fails, maybe paths aren't found or graph is too large. Safe fallback to unknown.
			finding.Reachability = "unknown"
			continue
		}

		// 3. Parse output. The paths algorithm outputs JSON.
		var pathsResult []interface{}
		if err := json.Unmarshal(output, &pathsResult); err != nil {
			// If we can't parse it, it means no paths were found or output is empty.
			// However, if the package is in the SBOM but not reachable in the CPG, it's dormant.
			if len(strings.TrimSpace(string(output))) == 0 || string(output) == "[]\n" {
				finding.Reachability = "unreachable"
			} else {
				finding.Reachability = "unknown"
			}
			continue
		}

		if len(pathsResult) > 0 {
			finding.Reachability = "reachable"
			finding.CallPath = []string{"Entrypoint", "...", finding.Package}
		} else {
			finding.Reachability = "unreachable"
		}
	}
	return nil
}
