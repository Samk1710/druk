package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// LLMClient represents a generic OpenAI-compatible API client
type LLMClient struct {
	BaseURL string
	APIKey  string
	Model   string
}

// NewClient initializes the LLM client based on environment variables.
// Prioritizes Groq if DRUK_GROQ_API_KEY is present.
func NewClient() (*LLMClient, error) {
	key := os.Getenv("DRUK_GROQ_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("DRUK_GROQ_API_KEY not set")
	}

	return &LLMClient{
		BaseURL: "https://api.groq.com/openai/v1/chat/completions",
		APIKey:  key,
		Model:   "llama3-8b-8192", // Fast default for reasoning
	}, nil
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	Temperature float64   `json:"temperature"`
	ResponseFormat struct {
		Type string `json:"type"`
	} `json:"response_format,omitempty"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Generate sends a prompt to the LLM and requests JSON output.
func (c *LLMClient) Generate(systemPrompt, userPrompt string) (string, error) {
	reqBody := chatRequest{
		Model:       c.Model,
		Temperature: 0.1,
		Messages: []message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}
	reqBody.ResponseFormat.Type = "json_object"

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", err
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}

	return chatResp.Choices[0].Message.Content, nil
}
