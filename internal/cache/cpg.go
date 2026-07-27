package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

func GetCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".druk", "cache")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

// ComputeHash computes a quick hash of the project dependencies or source code
// to determine if we need to regenerate the CPG.
func ComputeHash(repoPath string) (string, error) {
	// For a real implementation, we might hash go.mod, go.sum, package.json, package-lock.json, etc.
	// For now, we will hash a combination of known manifest files.
	manifests := []string{
		"go.mod", "go.sum",
		"package.json", "package-lock.json",
		"requirements.txt", "pyproject.toml",
	}

	h := sha256.New()
	foundAny := false

	for _, m := range manifests {
		path := filepath.Join(repoPath, m)
		if f, err := os.Open(path); err == nil {
			foundAny = true
			io.Copy(h, f)
			f.Close()
		}
	}

	// If no manifests are found, just hash the absolute path to isolate it, though it won't invalidate on changes.
	if !foundAny {
		h.Write([]byte(repoPath))
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
