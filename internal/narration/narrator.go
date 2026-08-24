// Package narration provides ATT&CK technique lookup and LLM narration via Ollama or Cloud LLM APIs.
package narration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Narrator interfaces with Ollama or Cloud LLM APIs (OpenAI-compatible) for LLM-grounded narration.
type Narrator struct {
	endpoint string
	model    string
	apiKey   string
	provider string // "ollama", "openai"
	timeout  time.Duration
	logger   *slog.Logger
	enabled  bool
}

// NarratorConfig configures the LLM narrator.
type NarratorConfig struct {
	Endpoint    string
	Model       string
	APIKey      string
	Provider    string // "auto", "ollama", "openai"
	TimeoutSecs int
	Enabled     bool
}

// DefaultNarratorConfig returns the default narrator configuration.
func DefaultNarratorConfig() NarratorConfig {
	return NarratorConfig{
		Endpoint:    "http://localhost:11434",
		Model:       "phi3:mini",
		Provider:    "auto",
		TimeoutSecs: 10,
		Enabled:     true,
	}
}

// NewNarrator creates a narrator instance.
func NewNarrator(cfg NarratorConfig, logger *slog.Logger) *Narrator {
	provider := strings.ToLower(cfg.Provider)
	if provider == "" || provider == "auto" {
		if strings.Contains(cfg.Endpoint, "11434") || strings.HasSuffix(cfg.Endpoint, "/api/generate") {
			provider = "ollama"
		} else {
			provider = "openai"
		}
	}

	return &Narrator{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		model:    cfg.Model,
		apiKey:   cfg.APIKey,
		provider: provider,
		timeout:  time.Duration(cfg.TimeoutSecs) * time.Second,
		logger:   logger,
		enabled:  cfg.Enabled,
	}
}

// NarrationInput holds the structured context for narration.
type NarrationInput struct {
	PID               uint32        `json:"pid"`
	Comm              string        `json:"comm"`
	TrustScore        float64       `json:"trust_score"`
	ConformalPValue   float64       `json:"conformal_p_value"`
	ResponseTier      string        `json:"response_tier"`
	MatchedTechniques []AttackEntry `json:"matched_techniques"`
	CausalSummary     string        `json:"causal_summary"`
	Action            string        `json:"action"`
}

// NarrationResult holds the LLM narration output.
type NarrationResult struct {
	Narrative    string   `json:"narrative"`
	TechniqueIDs []string `json:"technique_ids"` // Only from lookup table
	Model        string   `json:"model"`
	LatencyMs    int64    `json:"latency_ms"`
}

// Narrate generates a grounded narrative for a security event.
// The LLM narrates around retrieved ATT&CK IDs — never generates IDs from scratch.
func (n *Narrator) Narrate(ctx context.Context, input NarrationInput) (*NarrationResult, error) {
	if !n.enabled {
		return n.fallbackNarration(input), nil
	}

	// Build grounded prompt
	prompt := n.buildPrompt(input)

	start := time.Now()
	var response string
	var err error

	if n.provider == "openai" {
		response, err = n.callOpenAI(ctx, prompt)
	} else {
		response, err = n.callOllama(ctx, prompt)
	}
	latency := time.Since(start).Milliseconds()

	if err != nil {
		n.logger.Warn("LLM narration failed, using fallback", "error", err, "latency_ms", latency, "provider", n.provider)
		return n.fallbackNarration(input), nil
	}

	// Extract only the technique IDs that were in the lookup table input
	techniqueIDs := make([]string, 0, len(input.MatchedTechniques))
	for _, t := range input.MatchedTechniques {
		techniqueIDs = append(techniqueIDs, t.TechniqueID)
	}

	return &NarrationResult{
		Narrative:    response,
		TechniqueIDs: techniqueIDs,
		Model:        n.model,
		LatencyMs:    latency,
	}, nil
}

// QueryCopilot sends a direct conversational query to the LLM.
func (n *Narrator) QueryCopilot(ctx context.Context, prompt string) (string, error) {
	if !n.enabled {
		return "AI Copilot is currently offline. Enable narration flag to activate.", nil
	}

	start := time.Now()
	var response string
	var err error

	if n.provider == "openai" {
		response, err = n.callOpenAI(ctx, prompt)
	} else {
		response, err = n.callOllama(ctx, prompt)
	}

	latency := time.Since(start).Milliseconds()
	if err != nil {
		n.logger.Warn("Copilot LLM query failed", "error", err, "latency_ms", latency)
		return "", err
	}

	return response, nil
}


func (n *Narrator) buildPrompt(input NarrationInput) string {
	var sb strings.Builder
	sb.WriteString("You are a security analyst. Narrate this security event concisely.\n\n")
	sb.WriteString("RULES:\n")
	sb.WriteString("- Only reference the ATT&CK technique IDs provided below\n")
	sb.WriteString("- Do NOT invent or guess technique IDs\n")
	sb.WriteString("- Be concise (2-4 sentences)\n")
	sb.WriteString("- Focus on what happened and why it matters\n\n")

	sb.WriteString(fmt.Sprintf("PROCESS: %s (PID %d)\n", input.Comm, input.PID))
	sb.WriteString(fmt.Sprintf("TRUST SCORE: %.1f/100\n", input.TrustScore))
	sb.WriteString(fmt.Sprintf("CONFORMAL P-VALUE: %.4f\n", input.ConformalPValue))
	sb.WriteString(fmt.Sprintf("RESPONSE TIER: %s\n", input.ResponseTier))
	sb.WriteString(fmt.Sprintf("ACTION TAKEN: %s\n", input.Action))

	if len(input.MatchedTechniques) > 0 {
		sb.WriteString("\nMATCHED ATT&CK TECHNIQUES (from lookup table):\n")
		for _, t := range input.MatchedTechniques {
			sb.WriteString(fmt.Sprintf("- %s: %s (%s) — %s\n", t.TechniqueID, t.Technique, t.Tactic, t.Description))
		}
	}

	if input.CausalSummary != "" {
		sb.WriteString(fmt.Sprintf("\nCAUSAL GRAPH CONTEXT: %s\n", input.CausalSummary))
	}

	sb.WriteString("\nNarrate this event:")
	return sb.String()
}

// ollamaRequest is the Ollama API request payload.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// ollamaResponse is the Ollama API response payload.
type ollamaResponse struct {
	Response string `json:"response"`
}

func (n *Narrator) callOllama(ctx context.Context, prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()

	reqBody, _ := json.Marshal(ollamaRequest{
		Model:  n.model,
		Prompt: prompt,
		Stream: false,
	})

	url := n.endpoint
	if !strings.HasSuffix(url, "/api/generate") {
		url += "/api/generate"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+n.apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(body))
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	return result.Response, nil
}

// openAIRequest represents an OpenAI chat completions payload.
type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (n *Narrator) callOpenAI(ctx context.Context, prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()

	reqBody, _ := json.Marshal(openAIRequest{
		Model: n.model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
	})

	url := n.endpoint
	if strings.HasSuffix(url, "/chat/completions") {
		// already has full path
	} else if strings.HasSuffix(url, "/v1") {
		url += "/chat/completions"
	} else {
		url += "/v1/chat/completions"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("creating openai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+n.apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling cloud llm api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("cloud llm api returned %d: %s", resp.StatusCode, string(body))
	}

	var result openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding cloud llm response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty choices from cloud llm api")
	}

	return result.Choices[0].Message.Content, nil
}

// fallbackNarration generates a template-based narrative when LLM is unavailable.
func (n *Narrator) fallbackNarration(input NarrationInput) *NarrationResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Process %s (PID %d) triggered a %s-tier security response. ", input.Comm, input.PID, input.ResponseTier))
	sb.WriteString(fmt.Sprintf("Trust score: %.1f/100 (conformal p-value: %.4f). ", input.TrustScore, input.ConformalPValue))

	techniqueIDs := make([]string, 0, len(input.MatchedTechniques))
	if len(input.MatchedTechniques) > 0 {
		var techniqueStrs []string
		for _, t := range input.MatchedTechniques {
			techniqueStrs = append(techniqueStrs, fmt.Sprintf("%s (%s)", t.TechniqueID, t.Technique))
			techniqueIDs = append(techniqueIDs, t.TechniqueID)
		}
		sb.WriteString(fmt.Sprintf("Matched ATT&CK techniques: %s. ", strings.Join(techniqueStrs, ", ")))
	}

	sb.WriteString(fmt.Sprintf("Action: %s.", input.Action))

	return &NarrationResult{
		Narrative:    sb.String(),
		TechniqueIDs: techniqueIDs,
		Model:        "template-fallback",
		LatencyMs:    0,
	}
}

// IsAvailable checks if the LLM Endpoint is reachable.
func (n *Narrator) IsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	url := n.endpoint
	if n.provider == "openai" {
		if strings.HasSuffix(url, "/models") {
			// ok
		} else if strings.HasSuffix(url, "/v1") {
			url += "/models"
		} else {
			url += "/v1/models"
		}
	} else {
		if !strings.HasSuffix(url, "/api/tags") {
			url += "/api/tags"
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	if n.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+n.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
}


