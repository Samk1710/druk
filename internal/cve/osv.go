package cve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/samk/druk/internal/model"
)

type osvPackage struct {
	Purl string `json:"purl"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
}

type osvRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Modified string   `json:"modified"`
}

type osvResult struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvResponse struct {
	Results []osvResult `json:"results"`
}

const osvURL = "https://api.osv.dev/v1/querybatch"

func QueryOSV(components []model.Component) ([]model.Finding, error) {
	var purls []string
	for _, c := range components {
		if c.Purl != "" {
			purls = append(purls, c.Purl)
		}
	}

	if len(purls) == 0 {
		return nil, nil
	}

	chunkSize := 1000 // OSV supports up to 1000 queries per batch
	var allFindings []model.Finding

	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < len(purls); i += chunkSize {
		end := i + chunkSize
		if end > len(purls) {
			end = len(purls)
		}
		chunk := purls[i:end]

		var queries []osvQuery
		for _, p := range chunk {
			queries = append(queries, osvQuery{Package: osvPackage{Purl: p}})
		}

		reqBody, _ := json.Marshal(osvRequest{Queries: queries})
		
		req, err := http.NewRequest("POST", osvURL, bytes.NewBuffer(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to query OSV API: %w", err)
		}

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("OSV returned status %d: %s", resp.StatusCode, string(body))
		}

		var apiResp osvResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode OSV response: %w", err)
		}
		resp.Body.Close()

		for _, result := range apiResp.Results {
			for _, vuln := range result.Vulns {
				allFindings = append(allFindings, model.Finding{
					ID:       vuln.ID,
					Aliases:  vuln.Aliases,
					Severity: "UNKNOWN",
				})
			}
		}
	}

	return allFindings, nil
}
