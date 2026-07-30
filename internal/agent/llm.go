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
	Model          string    `json:"model"`
	Messages       []Message `json:"messages"`
	Temperature    float64   `json:"temperature"`
	ResponseFormat *struct {
		Type string `json:"type"`
	} `json:"response_format,omitempty"`
	Tools []Tool `json:"tools,omitempty"`
}

type Message struct {
	Role       string      `json:"role"`
	Content    string      `json:"content,omitempty"`
	Name       string      `json:"name,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Parameters  interface{} `json:"parameters"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

// Generate sends a prompt to the LLM and requests JSON output.
func (c *LLMClient) Generate(systemPrompt, userPrompt string) (string, error) {
	reqBody := chatRequest{
		Model:       c.Model,
		Temperature: 0.1,
		Messages: []Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		ResponseFormat: &struct {
			Type string `json:"type"`
		}{Type: "json_object"},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	respMsg, err := c.doRequest(jsonData)
	if err != nil {
		return "", err
	}
	return respMsg.Content, nil
}

// Chat sends a full conversation history and optional tools to the LLM.
func (c *LLMClient) Chat(messages []Message, tools []Tool) (Message, error) {
	reqBody := chatRequest{
		Model:       c.Model,
		Temperature: 0.1,
		Messages:    messages,
		Tools:       tools,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return Message{}, err
	}

	return c.doRequest(jsonData)
}

func (c *LLMClient) doRequest(jsonData []byte) (Message, error) {
	req, err := http.NewRequest("POST", c.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return Message{}, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return Message{}, err
	}

	if len(chatResp.Choices) == 0 {
		return Message{}, fmt.Errorf("no response choices returned")
	}

	return chatResp.Choices[0].Message, nil
}
