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
      cooldown-jitter-percent: 10
      penalty-rules:
        - name: subscription
          status: 402
          match: ["Check your subscription", "Check your subscription"]
          match-regexr: ["subscription.*required", "["]
          initial-cooldown-seconds: 3600
          max-cooldown-seconds: 864000
          backoff-factor: 6
      probe-model: mistral-small-latest
      probe-interval-seconds: 3
      probe-concurrency: 4
      manual-test-concurrency: 8
      manual-test-max-models: 5
      manual-test-timeout-seconds: 45
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
	if policy.CooldownJitterPercent != 10 || len(policy.PenaltyRules) != 1 {
		t.Fatalf("penalty policy = %+v", policy)
	}
	rule := policy.PenaltyRules[0]
	if rule.Name != "subscription" || rule.Status != 402 || len(rule.Match) != 1 || len(rule.MatchRegexr) != 1 || rule.InitialCooldownSeconds != 3600 || rule.MaxCooldownSeconds != 864000 || rule.BackoffFactor != 6 {
		t.Fatalf("penalty rule = %+v", rule)
	}
	if policy.ProbeModel != "mistral-small-latest" || policy.ProbeIntervalSeconds != 3 || policy.ProbeConcurrency != 4 {
		t.Fatalf("probe policy = %+v", policy)
	}
	if policy.ManualTestConcurrency != 8 || policy.ManualTestMaxModels != 5 || policy.ManualTestTimeoutSeconds != 45 {
		t.Fatalf("manual test policy = %+v", policy)
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
	if got.InitialCooldownSeconds != 60 || got.MaxCooldownSeconds != 1800 || got.BackoffFactor != 2 || got.CooldownJitterPercent != 0 {
		t.Fatalf("default cooldown policy = %+v", got)
	}
	if got.ProbeModel != "probe-model" || got.ProbeIntervalSeconds != 5 || got.ProbeConcurrency != 2 {
		t.Fatalf("default probe policy = %+v", got)
	}
	if got.ManualTestConcurrency != 4 || got.ManualTestMaxModels != 3 || got.ManualTestTimeoutSeconds != 30 {
		t.Fatalf("default manual test policy = %+v", got)
	}

	rulesOnly := NormalizeOpenAICompatibilityCredentialPolicy(&OpenAICompatibilityCredentialPolicy{
		InitialCooldownSeconds: 9999999,
		MaxCooldownSeconds:     9999999,
		CooldownJitterPercent:  99,
		PenaltyRules: []OpenAICompatibilityCredentialPolicyRule{{
			Status: 402,
		}},
	})
	if rulesOnly == nil || len(rulesOnly.PenaltyRules) != 1 {
		t.Fatalf("rules-only policy = %+v", rulesOnly)
	}
	if rulesOnly.InitialCooldownSeconds != 864000 || rulesOnly.MaxCooldownSeconds != 864000 || rulesOnly.CooldownJitterPercent != 50 {
		t.Fatalf("rules-only clamps = %+v", rulesOnly)
	}
}
