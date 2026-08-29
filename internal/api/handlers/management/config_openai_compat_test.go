package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestGetOpenAICompatIncludesDisableCooling(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	requestRetry := 0
	maxRetryCredentials := 4
	disableCooling := true
	credentialPolicy := &config.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusUnauthorized, http.StatusPaymentRequired},
		InitialCooldownSeconds: 60,
		MaxCooldownSeconds:     864000,
		BackoffFactor:          5,
		CooldownJitterPercent:  10,
		PenaltyRules: []config.OpenAICompatibilityCredentialPolicyRule{{
			Name:                   "subscription",
			Status:                 http.StatusPaymentRequired,
			Match:                  []string{"Check your subscription"},
			InitialCooldownSeconds: 3600,
			MaxCooldownSeconds:     864000,
			BackoffFactor:          5,
		}},
		ProbeModel:               "mistral-small-latest",
		ProbeIntervalSeconds:     5,
		ProbeConcurrency:         4,
		ManualTestConcurrency:    4,
		ManualTestMaxModels:      3,
		ManualTestTimeoutSeconds: 30,
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "Mimo CN",
				BaseURL: "https://token-plan-cn.xiaomimimo.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "test-key"},
				},
				Models: []config.OpenAICompatibilityModel{
					{Name: "mimo-v2.5", Alias: ""},
				},
				SupportPromptCacheKey: true,
				DisableCooling:        &disableCooling,
				RequestRetry:          &requestRetry,
				MaxRetryCredentials:   &maxRetryCredentials,
				CredentialPolicy:      credentialPolicy,
			},
		},
	}, nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/openai-compatibility", nil)
	h.GetOpenAICompat(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var body struct {
		OpenAICompatibility []struct {
			SupportPromptCacheKey *bool                                       `json:"support-prompt-cache-key"`
			DisableCooling        *bool                                       `json:"disable-cooling"`
			RequestRetry          *int                                        `json:"request-retry"`
			MaxRetryCredentials   *int                                        `json:"max-retry-credentials"`
			CredentialPolicy      *config.OpenAICompatibilityCredentialPolicy `json:"credential-policy"`
		} `json:"openai-compatibility"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(body.OpenAICompatibility) != 1 {
		t.Fatalf("expected 1 openai-compatibility entry, got %d", len(body.OpenAICompatibility))
	}
	if body.OpenAICompatibility[0].SupportPromptCacheKey == nil || !*body.OpenAICompatibility[0].SupportPromptCacheKey {
		t.Fatalf("expected support-prompt-cache-key to be present and true, got %#v", body.OpenAICompatibility[0].SupportPromptCacheKey)
	}
	if body.OpenAICompatibility[0].DisableCooling == nil || !*body.OpenAICompatibility[0].DisableCooling {
		t.Fatalf("expected disable-cooling to be present and true, got %#v", body.OpenAICompatibility[0].DisableCooling)
	}
	if body.OpenAICompatibility[0].RequestRetry == nil || *body.OpenAICompatibility[0].RequestRetry != 0 {
		t.Fatalf("expected request-retry to be present and 0, got %#v", body.OpenAICompatibility[0].RequestRetry)
	}
	if body.OpenAICompatibility[0].MaxRetryCredentials == nil || *body.OpenAICompatibility[0].MaxRetryCredentials != 4 {
		t.Fatalf("expected max-retry-credentials to be present and 4, got %#v", body.OpenAICompatibility[0].MaxRetryCredentials)
	}
	if policy := body.OpenAICompatibility[0].CredentialPolicy; policy == nil || len(policy.ScopeStatuses) != 2 || policy.BackoffFactor != 5 || policy.ProbeConcurrency != 4 || policy.CooldownJitterPercent != 10 || len(policy.PenaltyRules) != 1 || policy.ManualTestTimeoutSeconds != 30 {
		t.Fatalf("expected credential-policy to be present, got %#v", policy)
	}
}

func TestPatchOpenAICompatCredentialPolicy(t *testing.T) {
	cfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{{
		Name:          "mistral",
		BaseURL:       "https://api.mistral.ai/v1",
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "test-key"}},
	}}}
	h := &Handler{cfg: cfg, configFilePath: writeTestConfigFile(t)}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/openai-compatibility", strings.NewReader(`{
  "index": 0,
  "value": {
    "max-retry-credentials": 4,
    "credential-policy": {
      "scope-statuses": [402, 401, 402, 200],
      "initial-cooldown-seconds": 60,
      "max-cooldown-seconds": 21600,
      "backoff-factor": 5,
      "cooldown-jitter-percent": 10,
      "penalty-rules": [{
        "name": "subscription",
        "status": 402,
        "match": ["Check your subscription"],
        "initial-cooldown-seconds": 3600,
        "max-cooldown-seconds": 864000,
        "backoff-factor": 5
      }],
      "probe-model": " mistral-small-latest ",
      "probe-interval-seconds": 5,
      "probe-concurrency": 4,
      "manual-test-concurrency": 4,
      "manual-test-max-models": 3,
      "manual-test-timeout-seconds": 30
    }
  }
}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.PatchOpenAICompat(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	entry := cfg.OpenAICompatibility[0]
	if entry.MaxRetryCredentials == nil || *entry.MaxRetryCredentials != 4 {
		t.Fatalf("max-retry-credentials = %v, want 4", entry.MaxRetryCredentials)
	}
	policy := entry.CredentialPolicy
	if policy == nil || len(policy.ScopeStatuses) != 2 || policy.ScopeStatuses[0] != 401 || policy.ScopeStatuses[1] != 402 {
		t.Fatalf("credential-policy statuses = %#v", policy)
	}
	if policy.ProbeModel != "mistral-small-latest" || policy.BackoffFactor != 5 || policy.ProbeConcurrency != 4 || policy.CooldownJitterPercent != 10 || len(policy.PenaltyRules) != 1 || policy.PenaltyRules[0].Name != "subscription" || policy.ManualTestConcurrency != 4 || policy.ManualTestMaxModels != 3 || policy.ManualTestTimeoutSeconds != 30 {
		t.Fatalf("credential-policy = %#v", policy)
	}
}

func TestNormalizedOpenAICompatibilityEntriesDeepCopiesDeadCredentialPolicy(t *testing.T) {
	dead := &config.OpenAICompatibilityDeadCredentialPolicy{
		Enabled:     true,
		Statuses:    []int{401},
		Match:       []string{"authentication failed"},
		MatchRegexr: []string{"^auth"},
	}
	entries := normalizedOpenAICompatibilityEntries([]config.OpenAICompatibility{{
		Name: "copy-test",
		CredentialPolicy: &config.OpenAICompatibilityCredentialPolicy{
			DeadCredential: dead,
		},
	}})
	if len(entries) != 1 || entries[0].CredentialPolicy == nil || entries[0].CredentialPolicy.DeadCredential == nil {
		t.Fatalf("normalized entries = %#v", entries)
	}

	entries[0].CredentialPolicy.DeadCredential.Statuses[0] = 403
	entries[0].CredentialPolicy.DeadCredential.Match[0] = "changed"
	entries[0].CredentialPolicy.DeadCredential.MatchRegexr[0] = "changed"
	if dead.Statuses[0] != 401 || dead.Match[0] != "authentication failed" || dead.MatchRegexr[0] != "^auth" {
		t.Fatalf("dead credential policy shares mutable storage: %+v", dead)
	}
}
