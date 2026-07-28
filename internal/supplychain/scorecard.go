package supplychain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/samk/druk/internal/model"
)

type scorecardResponse struct {
	Score float64 `json:"score"`
	Checks []struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Reason string `json:"reason"`
		Details []string `json:"details"`
	} `json:"checks"`
}

// FetchScorecard attempts to fetch the OpenSSF Scorecard for the given local repository path.
// It tries to find the github remote origin. If it fails, it returns an empty SupplyChain gracefully.
func FetchScorecard(repoPath string) model.SupplyChain {
	// 1. Get git remote origin
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return model.SupplyChain{} // Not a git repo or no origin
	}

	remoteURL := strings.TrimSpace(string(out))
	// Parse github.com:owner/repo.git or https://github.com/owner/repo.git
	var ownerRepo string
	if strings.Contains(remoteURL, "github.com") {
		parts := strings.Split(remoteURL, "github.com")
		if len(parts) > 1 {
			ownerRepo = parts[1]
			ownerRepo = strings.TrimPrefix(ownerRepo, ":")
			ownerRepo = strings.TrimPrefix(ownerRepo, "/")
			ownerRepo = strings.TrimSuffix(ownerRepo, ".git")
		}
	}

	if ownerRepo == "" {
		return model.SupplyChain{} // Not a recognized GitHub repo
	}

	// 2. Query OpenSSF API
	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/github.com/%s", ownerRepo)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return model.SupplyChain{} // API failed or not found (maybe private repo)
	}
	defer resp.Body.Close()

	var apiResp scorecardResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return model.SupplyChain{}
	}

	// 3. Map to our model
	sc := model.SupplyChain{
		Score:       apiResp.Score,
		IsScorecard: true,
	}

	for _, check := range apiResp.Checks {
		sc.Checks = append(sc.Checks, model.ScorecardCheck{
			Name:   check.Name,
			Score:  check.Score,
			Reason: check.Reason,
		})
	}

	return sc
}
