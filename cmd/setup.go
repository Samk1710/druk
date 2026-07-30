package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup Druk dependencies (Syft, Semgrep, Gitleaks, AppThreat)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Setting up Druk dependencies...")

		// Create ~/.druk/bin
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to get home dir: %v\n", err)
			os.Exit(1)
		}

		drukDir := filepath.Join(home, ".druk", "bin")
		if err := os.MkdirAll(drukDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create %s: %v\n", drukDir, err)
			os.Exit(1)
		}

		fmt.Printf("[+] Created %s\n", drukDir)

		// Check for Semgrep
		if _, err := exec.LookPath("semgrep"); err != nil {
			fmt.Println("[-] Semgrep is missing. Install via: python3 -m pip install semgrep")
		} else {
			fmt.Println("[+] Semgrep found")
		}

		// Check for Syft
		if _, err := exec.LookPath("syft"); err != nil {
			fmt.Println("[-] Syft is missing. Install via: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin")
		} else {
			fmt.Println("[+] Syft found")
		}

		// Check for Gitleaks
		if _, err := exec.LookPath("gitleaks"); err != nil {
			fmt.Println("[-] Gitleaks is missing. Install via: brew install gitleaks")
		} else {
			fmt.Println("[+] Gitleaks found")
		}

		fmt.Println("[*] Setup complete. (Optional) Export DRUK_GROQ_API_KEY for AI features.")
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
