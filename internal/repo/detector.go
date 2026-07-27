package repo

import (
	"os"
	"path/filepath"
)

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DetectLanguage inspects the root of the path for known manifests and returns the primary language.
func DetectLanguage(path string) string {
	if fileExists(filepath.Join(path, "go.mod")) {
		return "Go"
	}
	if fileExists(filepath.Join(path, "package.json")) {
		return "JavaScript/TypeScript"
	}
	if fileExists(filepath.Join(path, "requirements.txt")) || fileExists(filepath.Join(path, "pyproject.toml")) {
		return "Python"
	}
	if fileExists(filepath.Join(path, "Cargo.toml")) {
		return "Rust"
	}
	if fileExists(filepath.Join(path, "pom.xml")) {
		return "Java"
	}
	if fileExists(filepath.Join(path, "Gemfile")) {
		return "Ruby"
	}

	return "Unknown"
}
