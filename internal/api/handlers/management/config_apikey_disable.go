package management

import (
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const configAPIKeyDisablePattern = "*"

// toggleConfigAPIKeyDisabled updates the explicit per-credential disabled flag
// for an OpenAI-compatible API-key entry. It resolves the entry by the stable
// runtime auth ID, so callers never need to send the credential material back
// through the management API.
func toggleConfigAPIKeyDisabled(cfg *config.Config, auth *coreauth.Auth, disable bool) (bool, error) {
	if cfg == nil || auth == nil || !coreauth.IsConfigAPIKeyAuth(auth) {
		return false, nil
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return false, fmt.Errorf("auth id is empty")
	}

	idGen := synthesizer.NewStableIDGenerator()
	for i := range cfg.OpenAICompatibility {
		entry := &cfg.OpenAICompatibility[i]
		if entry.Disabled {
			continue
		}
		providerName := strings.ToLower(strings.TrimSpace(entry.Name))
		if providerName == "" {
			providerName = "openai-compatibility"
		}
		idKind := fmt.Sprintf("openai-compatibility:%s", providerName)
		for j := range entry.APIKeyEntries {
			apiKeyEntry := &entry.APIKeyEntries[j]
			id, _ := idGen.Next(idKind, strings.TrimSpace(apiKeyEntry.APIKey), strings.TrimSpace(entry.BaseURL), strings.TrimSpace(apiKeyEntry.ProxyURL))
			if id != authID {
				continue
			}
			apiKeyEntry.Disabled = disable
			return true, nil
		}
	}
	return false, nil
}

func setConfigAPIKeyExcludedAll(models []string, disable bool) []string {
	if disable {
		for _, item := range models {
			if strings.TrimSpace(item) == configAPIKeyDisablePattern {
				return config.NormalizeExcludedModels(models)
			}
		}
		return config.NormalizeExcludedModels(append(append([]string(nil), models...), configAPIKeyDisablePattern))
	}
	filtered := make([]string, 0, len(models))
	for _, item := range models {
		if strings.TrimSpace(item) == configAPIKeyDisablePattern {
			continue
		}
		filtered = append(filtered, item)
	}
	return config.NormalizeExcludedModels(filtered)
}

func toggleConfigAPIKeyExcludedAll(cfg *config.Config, auth *coreauth.Auth, disable bool) (bool, error) {
	if cfg == nil || auth == nil || !coreauth.IsConfigAPIKeyAuth(auth) {
		return false, nil
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return false, fmt.Errorf("auth id is empty")
	}

	idGen := synthesizer.NewStableIDGenerator()

	for i := range cfg.GeminiKey {
		entry := &cfg.GeminiKey[i]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		prefix := strings.TrimSpace(entry.Prefix)
		if key == "" && base == "" {
			continue
		}
		id, _ := idGen.Next("gemini:apikey", key, base, proxyURL, prefix, config.FormatSortedHeaders(entry.Headers))
		if id == authID {
			entry.ExcludedModels = setConfigAPIKeyExcludedAll(entry.ExcludedModels, disable)
			return true, nil
		}
	}
	for i := range cfg.InteractionsKey {
		entry := &cfg.InteractionsKey[i]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		prefix := strings.TrimSpace(entry.Prefix)
		if key == "" && base == "" {
			continue
		}
		id, _ := idGen.Next("gemini-interactions:apikey", key, base, proxyURL, prefix, config.FormatSortedHeaders(entry.Headers))
		if id == authID {
			entry.ExcludedModels = setConfigAPIKeyExcludedAll(entry.ExcludedModels, disable)
			return true, nil
		}
	}
	for i := range cfg.ClaudeKey {
		entry := &cfg.ClaudeKey[i]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		prefix := strings.TrimSpace(entry.Prefix)
		if key == "" && base == "" {
			continue
		}
		id, _ := idGen.Next("claude:apikey", key, base, proxyURL, prefix, config.FormatSortedHeaders(entry.Headers))
		if id == authID {
			entry.ExcludedModels = setConfigAPIKeyExcludedAll(entry.ExcludedModels, disable)
			return true, nil
		}
	}
	for i := range cfg.CodexKey {
		entry := &cfg.CodexKey[i]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		prefix := strings.TrimSpace(entry.Prefix)
		if key == "" && base == "" {
			continue
		}
		id, _ := idGen.Next("codex:apikey", key, base, proxyURL, prefix, config.FormatSortedHeaders(entry.Headers))
		if id == authID {
			entry.ExcludedModels = setConfigAPIKeyExcludedAll(entry.ExcludedModels, disable)
			return true, nil
		}
	}
	for i := range cfg.XAIKey {
		entry := &cfg.XAIKey[i]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		prefix := strings.TrimSpace(entry.Prefix)
		if key == "" && base == "" {
			continue
		}
		id, _ := idGen.Next("xai:apikey", key, base, proxyURL, prefix, config.FormatSortedHeaders(entry.Headers))
		if id == authID {
			entry.ExcludedModels = setConfigAPIKeyExcludedAll(entry.ExcludedModels, disable)
			return true, nil
		}
	}
	for i := range cfg.VertexCompatAPIKey {
		entry := &cfg.VertexCompatAPIKey[i]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		proxy := strings.TrimSpace(entry.ProxyURL)
		id, _ := idGen.Next("vertex:apikey", key, base, proxy)
		if id == authID {
			entry.ExcludedModels = setConfigAPIKeyExcludedAll(entry.ExcludedModels, disable)
			return true, nil
		}
	}

	return false, nil
}
