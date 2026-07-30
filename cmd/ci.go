package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/samk/druk/internal/pipeline"
	"github.com/spf13/cobra"
)

var (
	failOn string
)

var ciCmd = &cobra.Command{
	Use:   "ci [target]",
	Short: "Run in non-interactive CI mode and exit non-zero on policy violations",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		// CI Mode is always headless and runs all determinisic scanners.
		// AI features are disabled by default for CI.
		report, err := pipeline.RunHeadless(target, true, true, true, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "CI pipeline error: %v\n", err)
			os.Exit(1)
		}

		// Evaluate policies
		var failures []string
		for _, f := range report.Findings {
			sev := strings.ToLower(f.Severity)
			isCrit := sev == "critical"
			isReachable := f.Reachability == "reachable"

			switch failOn {
			case "any-critical":
				if isCrit {
					failures = append(failures, fmt.Sprintf("Critical CVE found: %s in %s", f.ID, f.Package))
				}
			case "reachable-critical":
				if isCrit && isReachable {
					failures = append(failures, fmt.Sprintf("Reachable Critical CVE found: %s in %s (Path: %s)", f.ID, f.Package, strings.Join(f.CallPath, "->")))
				}
			}
		}

		if strings.HasPrefix(failOn, "score-below:") {
			parts := strings.Split(failOn, ":")
			if len(parts) == 2 {
				var threshold float64
				fmt.Sscanf(parts[1], "%f", &threshold)
				if report.SupplyChain.Score < threshold {
					failures = append(failures, fmt.Sprintf("Supply Chain Score %.1f is below threshold %.1f", report.SupplyChain.Score, threshold))
				}
			}
		}

		if len(failures) > 0 {
			fmt.Fprintf(os.Stderr, "CI Checks Failed:\n")
			for _, failure := range failures {
				fmt.Fprintf(os.Stderr, " - %s\n", failure)
			}
			os.Exit(1)
		}

		fmt.Println("CI Checks Passed!")
		os.Exit(0)
	},
}

func init() {
	ciCmd.Flags().StringVar(&failOn, "fail-on", "reachable-critical", "Policy to fail on: any-critical | reachable-critical | score-below:N")
	rootCmd.AddCommand(ciCmd)
}
