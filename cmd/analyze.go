package cmd

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/samk/druk/internal/tui"
	"github.com/spf13/cobra"
)

var (
	runSAST    bool
	runSecrets bool
	runSCA     bool
	runAll     bool
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

		autoStart := runSAST || runSecrets || runSCA || runAll

		sca := true
		sast := true
		secrets := true

		if autoStart {
			sca = runSCA || runAll
			sast = runSAST || runAll
			secrets = runSecrets || runAll
		}

		p := tea.NewProgram(tui.InitialModel(target, sca, sast, secrets, autoStart))
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
	rootCmd.AddCommand(analyzeCmd)
}
