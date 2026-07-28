package threatmodel

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/samk/druk/internal/model"
)

// Generate builds a deterministic STRIDE threat model by scanning the repository
// for assets and trust boundaries using heuristics.
func Generate(repoPath string) model.ThreatModel {
	tm := model.ThreatModel{
		Assets:          []string{},
		TrustBoundaries: []string{},
		STRIDE:          []model.STRIDERisk{},
	}

	hasDB := false
	hasAuth := false
	hasExternalAPI := false

	// Very simple recursive heuristic scan
	filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Skip noisy dirs
		if strings.Contains(path, "node_modules") || strings.Contains(path, ".git") || strings.Contains(path, "venv") {
			return nil
		}

		name := strings.ToLower(d.Name())
		
		// 1. Detect Databases (Assets)
		if strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".sqlite") || strings.HasSuffix(name, ".db") {
			hasDB = true
		}
		if name == "schema.prisma" || name == "models.py" {
			hasDB = true
		}

		// 2. Detect Auth / Trust Boundaries
		if strings.Contains(name, "auth") || strings.Contains(name, "login") || strings.Contains(name, "middleware") {
			hasAuth = true
		}
		if strings.Contains(name, "jwt") || strings.Contains(name, "oauth") {
			hasAuth = true
		}

		// 3. Detect External API calls
		if name == "client.go" || name == "requests.py" || strings.Contains(name, "fetch") {
			hasExternalAPI = true
		}

		return nil
	})

	// Build the Threat Model
	if hasDB {
		tm.Assets = append(tm.Assets, "Relational Database")
		tm.STRIDE = append(tm.STRIDE, model.STRIDERisk{
			Category:    "Information Disclosure",
			Description: "The database stores sensitive application state. An attacker could extract this data via SQL Injection or improper access controls.",
			Mitigation:  "Use Parameterized Queries / ORM. Ensure DB network access is restricted.",
		})
		tm.STRIDE = append(tm.STRIDE, model.STRIDERisk{
			Category:    "Tampering",
			Description: "An attacker could modify database records, corrupting application state.",
			Mitigation:  "Implement strict role-based access control (RBAC) and validate all inputs.",
		})
	}

	if hasAuth {
		tm.TrustBoundaries = append(tm.TrustBoundaries, "Authentication/Authorization Middleware")
		tm.STRIDE = append(tm.STRIDE, model.STRIDERisk{
			Category:    "Spoofing",
			Description: "An attacker could forge authentication tokens (e.g., JWT) or steal credentials to impersonate users.",
			Mitigation:  "Use strong, signed tokens with short expirations. Store secrets securely. Enforce HTTPS.",
		})
		tm.STRIDE = append(tm.STRIDE, model.STRIDERisk{
			Category:    "Elevation of Privilege",
			Description: "A standard user could bypass authorization checks to perform administrative actions.",
			Mitigation:  "Enforce authorization checks on every endpoint, not just UI hiding.",
		})
	}

	if hasExternalAPI {
		tm.TrustBoundaries = append(tm.TrustBoundaries, "External API Clients")
		tm.STRIDE = append(tm.STRIDE, model.STRIDERisk{
			Category:    "Denial of Service",
			Description: "The application relies on external APIs. If they go down or rate limit, the application could crash or hang.",
			Mitigation:  "Implement timeouts, retries with exponential backoff, and circuit breakers.",
		})
	}

	return tm
}
