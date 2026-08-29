package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestSetConfigAPIKeyExcludedAll(t *testing.T) {
	gotDisable := setConfigAPIKeyExcludedAll([]string{"gpt-5"}, true)
	if len(gotDisable) != 2 || gotDisable[0] != "gpt-5" || gotDisable[1] != "*" {
		t.Fatalf("unexpected disable list: %#v", gotDisable)
	}
	gotEnable := setConfigAPIKeyExcludedAll([]string{"gpt-5", "*"}, false)
	if len(gotEnable) != 1 || gotEnable[0] != "gpt-5" {
		t.Fatalf("unexpected enable list: %#v", gotEnable)
	}
}

func TestToggleConfigAPIKeyExcludedAll_XAI(t *testing.T) {
	cfg := &config.Config{
		XAIKey: []config.XAIKey{{
			APIKey:  "xai-test",
			BaseURL: "https://api.x.ai/v1",
		}},
	}
	idGen := synthesizer.NewStableIDGenerator()
	authID, _ := idGen.Next("xai:apikey", "xai-test", "https://api.x.ai/v1", "", "", "")
	auth := &coreauth.Auth{
		ID:       authID,
		Provider: "xai",
		Attributes: map[string]string{
			"api_key":  "xai-test",
			"base_url": "https://api.x.ai/v1",
			"source":   "config:xai[abc]",
		},
	}

	handled, errToggle := toggleConfigAPIKeyExcludedAll(cfg, auth, true)
	if errToggle != nil || !handled {
		t.Fatalf("toggle disable: handled=%v err=%v", handled, errToggle)
	}
	if len(cfg.XAIKey[0].ExcludedModels) != 1 || cfg.XAIKey[0].ExcludedModels[0] != "*" {
		t.Fatalf("excluded-models = %#v, want [*]", cfg.XAIKey[0].ExcludedModels)
	}
}

func TestToggleConfigAPIKeyDisabled_OpenAICompatibility(t *testing.T) {
	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:    "nvidia",
			BaseURL: "https://integrate.example/v1",
			APIKeyEntries: []config.OpenAICompatibilityAPIKey{
				{APIKey: "key-a"},
				{APIKey: "key-b"},
			},
		}},
	}
	idGen := synthesizer.NewStableIDGenerator()
	firstID, _ := idGen.Next("openai-compatibility:nvidia", "key-a", "https://integrate.example/v1", "")
	auth := &coreauth.Auth{
		ID:       firstID,
		Provider: "openai-compatible-nvidia",
		Attributes: map[string]string{
			"api_key":      "key-a",
			"base_url":     "https://integrate.example/v1",
			"compat_name":  "nvidia",
			"provider_key": "openai-compatible-nvidia",
			"source":       "config:nvidia[test]",
		},
	}

	handled, errToggle := toggleConfigAPIKeyDisabled(cfg, auth, true)
	if errToggle != nil || !handled {
		t.Fatalf("toggle disable: handled=%v err=%v", handled, errToggle)
	}
	if !cfg.OpenAICompatibility[0].APIKeyEntries[0].Disabled || cfg.OpenAICompatibility[0].APIKeyEntries[1].Disabled {
		t.Fatalf("disabled entries = %+v", cfg.OpenAICompatibility[0].APIKeyEntries)
	}
	handled, errToggle = toggleConfigAPIKeyDisabled(cfg, auth, false)
	if errToggle != nil || !handled {
		t.Fatalf("toggle enable: handled=%v err=%v", handled, errToggle)
	}
	if cfg.OpenAICompatibility[0].APIKeyEntries[0].Disabled {
		t.Fatal("explicit disabled flag was not cleared")
	}
}

func TestPatchAuthFileStatus_OpenAICompatibilityUsesExplicitDisabled(t *testing.T) {
	cfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{{
		Name:          "nvidia",
		BaseURL:       "https://integrate.example/v1",
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "key-a"}},
	}}}
	configPath := writeTestConfigFile(t)
	manager := coreauth.NewManager(nil, nil, nil)
	synth := synthesizer.NewConfigSynthesizer()
	auths, errSynthesize := synth.Synthesize(&synthesizer.SynthesisContext{
		Config:      cfg,
		IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if errSynthesize != nil || len(auths) != 1 {
		t.Fatalf("synthesize auths: count=%d err=%v", len(auths), errSynthesize)
	}
	if _, errRegister := manager.Register(context.Background(), auths[0]); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	h := NewHandler(cfg, configPath, manager)
	defer h.Close()

	patch := func(disabled bool) (int, map[string]any) {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"`+auths[0].ID+`","disabled":`+strconv.FormatBool(disabled)+`}`))
		h.PatchAuthFileStatus(ctx)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	status, body := patch(true)
	if status != http.StatusOK || body["via"] != "config:disabled" {
		t.Fatalf("disable response = %d %#v", status, body)
	}
	loaded, errLoad := config.LoadConfig(configPath)
	if errLoad != nil || !loaded.OpenAICompatibility[0].APIKeyEntries[0].Disabled {
		t.Fatalf("persisted disabled state = %+v err=%v", loaded, errLoad)
	}

	status, body = patch(false)
	if status != http.StatusOK || body["via"] != "config:disabled" {
		t.Fatalf("enable response = %d %#v", status, body)
	}
	loaded, errLoad = config.LoadConfig(configPath)
	if errLoad != nil || loaded.OpenAICompatibility[0].APIKeyEntries[0].Disabled {
		t.Fatalf("persisted enabled state = %+v err=%v", loaded, errLoad)
	}
}

func TestToggleConfigAPIKeyExcludedAll_Codex(t *testing.T) {
	cfg := &config.Config{
		CodexKey: []config.CodexKey{{
			APIKey:  "sk-test",
			BaseURL: "https://example.com/v1",
		}},
	}
	idGen := synthesizer.NewStableIDGenerator()
	authID, _ := idGen.Next("codex:apikey", "sk-test", "https://example.com/v1", "", "", "")
	auth := &coreauth.Auth{
		ID:       authID,
		Provider: "codex",
		Attributes: map[string]string{
			"api_key":  "sk-test",
			"base_url": "https://example.com/v1",
			"source":   "config:codex[abc]",
		},
	}

	handled, err := toggleConfigAPIKeyExcludedAll(cfg, auth, true)
	if err != nil || !handled {
		t.Fatalf("toggle disable: handled=%v err=%v", handled, err)
	}
	if len(cfg.CodexKey[0].ExcludedModels) != 1 || cfg.CodexKey[0].ExcludedModels[0] != "*" {
		t.Fatalf("expected excluded-models [*], got %#v", cfg.CodexKey[0].ExcludedModels)
	}

	handled, err = toggleConfigAPIKeyExcludedAll(cfg, auth, false)
	if err != nil || !handled {
		t.Fatalf("toggle enable: handled=%v err=%v", handled, err)
	}
	if len(cfg.CodexKey[0].ExcludedModels) != 0 {
		t.Fatalf("expected excluded-models cleared, got %#v", cfg.CodexKey[0].ExcludedModels)
	}
}

func TestToggleConfigAPIKeyExcludedAll_Vertex_NoBaseURL(t *testing.T) {
	cfg := &config.Config{
		VertexCompatAPIKey: []config.VertexCompatKey{{
			APIKey: "vertex-key-only",
		}},
	}
	idGen := synthesizer.NewStableIDGenerator()
	authID, _ := idGen.Next("vertex:apikey", "vertex-key-only", "", "")
	auth := &coreauth.Auth{
		ID:       authID,
		Provider: "vertex",
		Attributes: map[string]string{
			"auth_kind": "apikey",
			"api_key":   "vertex-key-only",
			"source":    "config:vertex[xyz]",
		},
	}

	handled, errToggle := toggleConfigAPIKeyExcludedAll(cfg, auth, true)
	if errToggle != nil || !handled {
		t.Fatalf("toggle disable: handled=%v err=%v", handled, errToggle)
	}
	if len(cfg.VertexCompatAPIKey[0].ExcludedModels) != 1 || cfg.VertexCompatAPIKey[0].ExcludedModels[0] != "*" {
		t.Fatalf("excluded-models = %#v, want [*]", cfg.VertexCompatAPIKey[0].ExcludedModels)
	}
}

func TestToggleConfigAPIKeyExcludedAll_EmptyKeyWithBaseURL(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:  "",
			BaseURL: "https://custom-claude.example.com",
		}},
		GeminiKey: []config.GeminiKey{{
			APIKey:  "   ",
			BaseURL: "https://custom-gemini.example.com",
		}},
	}
	idGen := synthesizer.NewStableIDGenerator()
	claudeID, _ := idGen.Next("claude:apikey", "", "https://custom-claude.example.com", "", "", "")
	geminiID, _ := idGen.Next("gemini:apikey", "", "https://custom-gemini.example.com", "", "", "")

	claudeAuth := &coreauth.Auth{
		ID:       claudeID,
		Provider: "claude",
		Attributes: map[string]string{
			"auth_kind": "apikey",
			"base_url":  "https://custom-claude.example.com",
			"source":    "config:claude[abc]",
		},
	}
	geminiAuth := &coreauth.Auth{
		ID:       geminiID,
		Provider: "gemini",
		Attributes: map[string]string{
			"auth_kind": "apikey",
			"base_url":  "https://custom-gemini.example.com",
			"source":    "config:gemini[def]",
		},
	}

	handled, err := toggleConfigAPIKeyExcludedAll(cfg, claudeAuth, true)
	if err != nil || !handled {
		t.Fatalf("toggle claude: handled=%v err=%v", handled, err)
	}
	if len(cfg.ClaudeKey[0].ExcludedModels) != 1 || cfg.ClaudeKey[0].ExcludedModels[0] != "*" {
		t.Fatalf("claude excluded-models = %#v, want [*]", cfg.ClaudeKey[0].ExcludedModels)
	}

	handled, err = toggleConfigAPIKeyExcludedAll(cfg, geminiAuth, true)
	if err != nil || !handled {
		t.Fatalf("toggle gemini: handled=%v err=%v", handled, err)
	}
	if len(cfg.GeminiKey[0].ExcludedModels) != 1 || cfg.GeminiKey[0].ExcludedModels[0] != "*" {
		t.Fatalf("gemini excluded-models = %#v, want [*]", cfg.GeminiKey[0].ExcludedModels)
	}
}
