package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"nirvishaai/backend/config"
	"nirvishaai/backend/scanner"
)

const openRouterURL = "https://openrouter.ai/api/v1/chat/completions"

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func AnalyzeVulnerabilities(checks []scanner.CheckResult) ([]scanner.AIVuln, error) {
	failed := filterFailed(checks)
	if len(failed) == 0 {
		return nil, nil
	}

	prompt := buildPrompt(failed)
	models := allModels()

	var lastErr error
	for _, model := range models {
		result, err := callOpenRouter(model, prompt)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all models failed, last error: %w", lastErr)
}

func allModels() []string {
	models := []string{config.App.OpenRouterModel}
	models = append(models, config.App.FallbackModels...)
	return models
}

func callOpenRouter(model, prompt string) ([]scanner.AIVuln, error) {
	payload := chatRequest{
		Model: model,
		Messages: []message{
			{Role: "system", Content: systemPrompt()},
			{Role: "user", Content: prompt},
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", openRouterURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.App.OpenRouterAPIKey)
	req.Header.Set("HTTP-Referer", "https://nirvishaai.com")
	req.Header.Set("X-Title", "NirvishaAI")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, err
	}
	if chatResp.Error != nil {
		return nil, fmt.Errorf("openrouter error: %s", chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("no response from model %s", model)
	}

	return parseAIResponse(chatResp.Choices[0].Message.Content)
}

func systemPrompt() string {
	return `তুমি NirvishaAI-এর security expert AI। তোমার কাজ হলো web security vulnerabilities বাংলায় ব্যাখ্যা করা।

প্রতিটা vulnerability-র জন্য তুমি JSON array return করবে এই format-এ:
[
  {
    "check_name": "check এর নাম",
    "explanation": "এই vulnerability কী সেটা বাংলায় সহজ ভাষায় ব্যাখ্যা করো (technical terms English-এ রাখো)",
    "risk_level": "Critical / High / Medium / Low",
    "how_to_exploit": "একজন attacker কীভাবে এই vulnerability exploit করতো সেটা বাংলায় লেখো",
    "how_to_fix": "কীভাবে এটা fix করতে হবে বাংলায় লেখো",
    "code_snippet": "Fix এর জন্য code example (যদি applicable হয়)"
  }
]

শুধু JSON return করবে, অন্য কোনো text নয়।`
}

func buildPrompt(checks []scanner.CheckResult) string {
	data, _ := json.MarshalIndent(checks, "", "  ")
	return fmt.Sprintf("এই vulnerabilities গুলো analyze করো এবং বাংলায় explain করো:\n\n%s", string(data))
}

func parseAIResponse(content string) ([]scanner.AIVuln, error) {
	// Strip markdown code blocks if present
	clean := content
	if len(clean) > 7 && clean[:7] == "```json" {
		clean = clean[7:]
	}
	if len(clean) > 3 && clean[:3] == "```" {
		clean = clean[3:]
	}
	if len(clean) > 3 && clean[len(clean)-3:] == "```" {
		clean = clean[:len(clean)-3]
	}

	var vulns []scanner.AIVuln
	if err := json.Unmarshal([]byte(clean), &vulns); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}
	return vulns, nil
}

func filterFailed(checks []scanner.CheckResult) []scanner.CheckResult {
	var failed []scanner.CheckResult
	for _, c := range checks {
		if !c.Passed {
			failed = append(failed, c)
		}
	}
	return failed
}
