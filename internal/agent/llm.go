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
	BaseURL       string
	APIKey        string
	Model         string
	FallbackModel string
}

// NewClient initializes the LLM client based on environment variables.
// Prioritizes DRUK_LLM_PROVIDER (groq, ollama). Defaults to groq.
func NewClient() (*LLMClient, error) {
	provider := os.Getenv("DRUK_LLM_PROVIDER")
	if provider == "" {
		provider = "groq"
	}

	if provider == "ollama" {
		baseURL := os.Getenv("DRUK_OLLAMA_URL")
		if baseURL == "" {
			baseURL = "http://localhost:11434/v1/chat/completions" // Ollama OpenAI compat layer
		}
		model := os.Getenv("DRUK_OLLAMA_MODEL")
		if model == "" {
			model = "llama3" // Default ollama model
		}
		return &LLMClient{
			BaseURL: baseURL,
			APIKey:  "ollama", // API Key is ignored by Ollama but needed for struct
			Model:   model,
		}, nil
	}

	// Default to Groq
	key := os.Getenv("DRUK_GROQ_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("DRUK_GROQ_API_KEY not set")
	}

	return &LLMClient{
		BaseURL:       "https://api.groq.com/openai/v1/chat/completions",
		APIKey:        key,
		Model:         "llama-3.1-8b-instant", // Fast default for reasoning
		FallbackModel: "llama3-8b-8192",       // Fallback if instant is decommissioned or fails
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
		if c.FallbackModel != "" {
			reqBody.Model = c.FallbackModel
			jsonData, _ = json.Marshal(reqBody)
			respMsgFallback, errFallback := c.doRequest(jsonData)
			if errFallback != nil {
				return "", fmt.Errorf("primary error: %v, fallback error: %v", err, errFallback)
			}
			return respMsgFallback.Content, nil
		}
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

	respMsg, err := c.doRequest(jsonData)
	if err != nil {
		if c.FallbackModel != "" {
			reqBody.Model = c.FallbackModel
			jsonData, _ = json.Marshal(reqBody)
			respMsgFallback, errFallback := c.doRequest(jsonData)
			if errFallback != nil {
				return Message{}, fmt.Errorf("primary error: %v, fallback error: %v", err, errFallback)
			}
			return respMsgFallback, nil
		}
		return Message{}, err
	}
	return respMsg, nil
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
