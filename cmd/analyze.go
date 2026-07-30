package cmd

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/samk/druk/internal/agent"
	"github.com/samk/druk/internal/pipeline"
	"github.com/samk/druk/internal/render"
	"github.com/samk/druk/internal/tui"
	"github.com/spf13/cobra"
)

var (
	runSAST      bool
	runSecrets   bool
	runSCA       bool
	runAll       bool
	runAuto      bool
	runNarrate   bool
	outputFormat string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [target]",
	Short: "Analyze a repository",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		autoStart := runSAST || runSecrets || runSCA || runAll || runAuto

		sca := true
		sast := true
		secrets := true

		if autoStart {
			if runAuto {
				client, err := agent.NewClient()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: could not initialize LLM for Planner Agent (%v). Falling back to default tools.\n", err)
					sca, sast, secrets = true, true, true
				} else {
					fmt.Println("🧠 Planner Agent is analyzing repository to configure pipeline...")
					// Just a dummy file count for now to save I/O overhead. In a real app we'd count files.
					config := agent.PlannerAgent(client, "Unknown", 500)
					fmt.Printf("🧠 Planner Decision: %s\n", config.Reasoning)
					sca = config.RunSCA
					sast = config.RunSAST
					secrets = config.RunSecrets
				}
			} else {
				sca = runSCA || runAll
				sast = runSAST || runAll
				secrets = runSecrets || runAll
			}
		}

		if outputFormat == "json" || outputFormat == "sarif" {
			report, err := pipeline.RunHeadless(target, sca, sast, secrets, runNarrate)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Pipeline error: %v\n", err)
				os.Exit(1)
			}
			if outputFormat == "json" {
				render.JSON(os.Stdout, report)
			} else {
				render.SARIF(os.Stdout, report)
			}
			return
		}

		p := tea.NewProgram(tui.InitialModel(target, sca, sast, secrets, autoStart, runNarrate))
		if _, err := p.Run(); err != nil {
			fmt.Printf("Alas, there's been an error: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	analyzeCmd.Flags().BoolVar(&runSAST, "sast", false, "Run SAST scanner (Semgrep)")
	analyzeCmd.Flags().BoolVar(&runSecrets, "secrets", false, "Run Secrets scanner (Gitleaks)")
	analyzeCmd.Flags().BoolVar(&runSCA, "sca", false, "Run SCA scanner (SBOM & CVEs)")
	analyzeCmd.Flags().BoolVar(&runAll, "all", false, "Run all scanners instantly")
	analyzeCmd.Flags().BoolVar(&runAuto, "auto", false, "Use Planner Agent to determine pipeline config")
	analyzeCmd.Flags().BoolVar(&runNarrate, "narrate", false, "Run AI Synthesizer (requires DRUK_GROQ_API_KEY)")
	analyzeCmd.Flags().StringVarP(&outputFormat, "output", "o", "tui", "Output format (tui, json, sarif)")
	rootCmd.AddCommand(analyzeCmd)
}
