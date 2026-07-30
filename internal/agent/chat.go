package agent

import (
	"github.com/samk/druk/internal/model"
)

// ChatLoop orchestrates the conversation. It sends the message history,
// executes any requested tools, and appends the results until the model returns a final text answer.
func ChatLoop(client *LLMClient, report *model.Report, messages []Message) ([]Message, error) {
	for {
		respMsg, err := client.Chat(messages, AvailableTools)
		if err != nil {
			return messages, err
		}

		messages = append(messages, respMsg)

		// If no tool calls, the model gave a text response.
		if len(respMsg.ToolCalls) == 0 {
			break
		}

		// Execute all tool calls
		for _, call := range respMsg.ToolCalls {
			resultStr, err := ExecuteTool(report, call)
			if err != nil {
				resultStr = "Error executing tool: " + err.Error()
			}
			
			// Append the tool result back to the messages
			toolMsg := Message{
				Role:       "tool",
				Content:    resultStr,
				ToolCallID: call.ID,
			}
			messages = append(messages, toolMsg)
		}
	}

	return messages, nil
}
