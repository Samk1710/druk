package cve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/samk/druk/internal/model"
)

type vcRequest struct {
	Purls []string `json:"purls"`
}

type vcSeverity struct {
	Value string `json:"value"`
}

type vcAdvisory struct {
	AdvisoryID string       `json:"advisory_id"`
	Aliases    []string     `json:"aliases"`
	Severities []vcSeverity `json:"severities"`
}

type vcPaginatedResponse struct {
	Count   int          `json:"count"`
	Results []vcAdvisory `json:"results"`
}

const vcURL = "https://public.vulnerablecode.io/api/v3/advisories/"
const userAgent = "VCIO_API_AGENT"

func QueryVulnerableCode(components []model.Component) ([]model.Finding, error) {
	var purls []string
	for _, c := range components {
		if c.Purl != "" {
			purls = append(purls, c.Purl)
		}
	}

	if len(purls) == 0 {
		return nil, nil
	}

	chunkSize := 50 // Be gentle on the API
	var allFindings []model.Finding

	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < len(purls); i += chunkSize {
		end := i + chunkSize
		if end > len(purls) {
			end = len(purls)
		}
		chunk := purls[i:end]

		reqBody, _ := json.Marshal(vcRequest{Purls: chunk})
		body, err := doRequestWithRetry(client, reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch from VulnerableCode: %w", err)
		}

		var advisories []vcAdvisory

		// Attempt to parse as array first
		if err := json.Unmarshal(body, &advisories); err != nil {
			// If not array, maybe paginated object?
			var paginated vcPaginatedResponse
			if err2 := json.Unmarshal(body, &paginated); err2 == nil && paginated.Results != nil {
				advisories = paginated.Results
			} else {
				// Failed both, ignore chunk
				continue
			}
		}

		for _, adv := range advisories {
			sevStr := "UNKNOWN"
			if len(adv.Severities) > 0 {
				sevStr = adv.Severities[0].Value
			}

			allFindings = append(allFindings, model.Finding{
				ID:       adv.AdvisoryID,
				Aliases:  adv.Aliases,
				Severity: sevStr,
			})
		}
	}

	return allFindings, nil
}

func doRequestWithRetry(client *http.Client, reqBody []byte) ([]byte, error) {
	maxRetries := 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", vcURL, bytes.NewBuffer(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)

		if apiKey := os.Getenv("VULNERABLECODE_API_KEY"); apiKey != "" {
			req.Header.Set("Authorization", "Token "+apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			if attempt == maxRetries {
				return nil, fmt.Errorf("rate limited after %d retries", maxRetries)
			}
			retryAfterStr := resp.Header.Get("Retry-After")
			retryAfterSec := 1
			if retryAfterStr != "" {
				if sec, err := strconv.Atoi(retryAfterStr); err == nil {
					retryAfterSec = sec
				}
			}
			time.Sleep(time.Duration(retryAfterSec) * time.Second)
			continue
		}

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
		}

		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	return nil, fmt.Errorf("request failed after retries")
}
