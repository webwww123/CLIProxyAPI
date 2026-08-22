package config

import "testing"

func TestParseConfigBytesOpenAICompatibilityCredentialPolicy(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`
openai-compatibility:
  - name: mistral
    base-url: https://api.mistral.ai/v1
    max-retry-credentials: 4
    credential-policy:
      scope-statuses: [402, 401, 402, 99]
      initial-cooldown-seconds: 30
      max-cooldown-seconds: 3600
      backoff-factor: 5
      probe-model: mistral-small-latest
      probe-interval-seconds: 3
      probe-concurrency: 4
    api-key-entries:
      - api-key: test-key
    models:
      - name: mistral-small-latest
        alias: test-model
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if len(cfg.OpenAICompatibility) != 1 {
		t.Fatalf("openai-compatibility count = %d, want 1", len(cfg.OpenAICompatibility))
	}
	entry := cfg.OpenAICompatibility[0]
	if entry.MaxRetryCredentials == nil || *entry.MaxRetryCredentials != 4 {
		t.Fatalf("max-retry-credentials = %v, want 4", entry.MaxRetryCredentials)
	}
	policy := entry.CredentialPolicy
	if policy == nil {
		t.Fatal("credential-policy = nil")
	}
	if len(policy.ScopeStatuses) != 2 || policy.ScopeStatuses[0] != 401 || policy.ScopeStatuses[1] != 402 {
		t.Fatalf("scope-statuses = %v, want [401 402]", policy.ScopeStatuses)
	}
	if policy.InitialCooldownSeconds != 30 || policy.MaxCooldownSeconds != 3600 || policy.BackoffFactor != 5 {
		t.Fatalf("cooldown policy = %+v", policy)
	}
	if policy.ProbeModel != "mistral-small-latest" || policy.ProbeIntervalSeconds != 3 || policy.ProbeConcurrency != 4 {
		t.Fatalf("probe policy = %+v", policy)
	}
}

func TestNormalizeOpenAICompatibilityCredentialPolicyDefaultsAndDisable(t *testing.T) {
	if got := NormalizeOpenAICompatibilityCredentialPolicy(&OpenAICompatibilityCredentialPolicy{ScopeStatuses: []int{200, 999}}); got != nil {
		t.Fatalf("invalid-only policy = %+v, want nil", got)
	}
	got := NormalizeOpenAICompatibilityCredentialPolicy(&OpenAICompatibilityCredentialPolicy{
		ScopeStatuses: []int{402},
		ProbeModel:    " probe-model ",
	})
	if got == nil {
		t.Fatal("normalized policy = nil")
	}
	if got.InitialCooldownSeconds != 60 || got.MaxCooldownSeconds != 1800 || got.BackoffFactor != 2 {
		t.Fatalf("default cooldown policy = %+v", got)
	}
	if got.ProbeModel != "probe-model" || got.ProbeIntervalSeconds != 5 || got.ProbeConcurrency != 2 {
		t.Fatalf("default probe policy = %+v", got)
	}
}
