package reachability

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/samk/druk/internal/cache"
)

// GenerateCPG uses atom to generate a Code Property Graph for the given repoPath.
// Returns the absolute path to the generated app.cpg file, or an error if generation fails.
func GenerateCPG(repoPath string, language string) (string, error) {
	// 1. Check if atom is installed
	_, err := exec.LookPath("atom")
	if err != nil {
		return "", fmt.Errorf("atom binary not found in PATH: %w", err)
	}

	// 2. Setup Cache
	cacheDir, err := cache.GetCacheDir()
	if err != nil {
		return "", fmt.Errorf("failed to get cache dir: %w", err)
	}
	
	repoHash, err := cache.ComputeHash(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to compute repo hash: %w", err)
	}

	cpgDir := filepath.Join(cacheDir, repoHash)
	if err := os.MkdirAll(cpgDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cpg cache dir: %w", err)
	}
	
	cpgPath := filepath.Join(cpgDir, "app.cpg")

	// 3. Check Cache
	if _, err := os.Stat(cpgPath); err == nil {
		// Cache hit! CPG already exists.
		return cpgPath, nil
	}

	// 4. Generate CPG
	cmd := exec.Command("atom", "-o", cpgPath, repoPath)
	cmd.Dir = repoPath
	
	// We map Druk's language strings to atom's expected language strings
	var atomLang string
	switch language {
	case "Go":
		atomLang = "golang"
	case "Python":
		atomLang = "python"
	case "JavaScript", "TypeScript":
		atomLang = "javascript"
	case "Java":
		atomLang = "java"
	}
	
	if atomLang != "" {
		cmd.Args = append(cmd.Args, "-l", atomLang)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("atom generation failed: %w\nOutput: %s", err, string(output))
	}

	return cpgPath, nil
}
