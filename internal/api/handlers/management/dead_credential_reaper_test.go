package management

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

func TestDeadCredentialErrorMatchesStatusAndPatterns(t *testing.T) {
	policy := &config.OpenAICompatibilityDeadCredentialPolicy{
		Statuses:      []int{http.StatusUnauthorized, http.StatusForbidden},
		Match:         []string{"invalid key"},
		MatchRegexr:   []string{"denied$"},
		Confirmations: 2,
	}

	tests := []struct {
		name string
		err  *coreauth.Error
		want bool
	}{
		{name: "status and substring", err: &coreauth.Error{HTTPStatus: http.StatusUnauthorized, Message: "Invalid Key"}, want: true},
		{name: "status and regex", err: &coreauth.Error{HTTPStatus: http.StatusForbidden, Message: "access denied"}, want: true},
		{name: "wrong status", err: &coreauth.Error{HTTPStatus: http.StatusPaymentRequired, Message: "invalid key"}, want: false},
		{name: "wrong body", err: &coreauth.Error{HTTPStatus: http.StatusUnauthorized, Message: "temporary failure"}, want: false},
		{name: "request scoped", err: coreauth.NewRequestScopedError("invalid key", http.StatusUnauthorized), want: false},
		{name: "forced cooldown", err: &coreauth.Error{Code: coreauth.ErrorCodeForceCooldown, HTTPStatus: http.StatusUnauthorized, Message: "operator requested cooldown"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deadCredentialErrorMatches(policy, tt.err); got != tt.want {
				t.Fatalf("deadCredentialErrorMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandlerRemoveDeadCredentialBatchRequiresUniqueIdentity(t *testing.T) {
	provider := util.OpenAICompatibleProviderKey("dead-test")
	cfg := &config.Config{
		CredentialInFlight: config.DefaultCredentialInFlightConfig(),
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:    "dead-test",
			BaseURL: "https://upstream.example/v1",
			CredentialPolicy: config.NormalizeOpenAICompatibilityCredentialPolicy(&config.OpenAICompatibilityCredentialPolicy{
				DeadCredential: &config.OpenAICompatibilityDeadCredentialPolicy{
					Enabled: true,
					Action:  "delete",
				},
			}),
			APIKeyEntries: []config.OpenAICompatibilityAPIKey{
				{APIKey: "key-a", ProxyURL: "http://proxy-a"},
				{APIKey: "key-a", ProxyURL: "http://proxy-b"},
				{APIKey: "key-b", ProxyURL: "http://proxy-a"},
			},
		}},
	}
	configPath := writeDeadCredentialTestConfig(t, cfg)
	h := &Handler{cfg: cfg, configFilePath: configPath}
	policyFingerprint := deadCredentialPolicyFingerprint(cfg.OpenAICompatibility[0].CredentialPolicy.DeadCredential)

	removed, backupDir, errRemove := h.removeDeadCredentialBatch(context.Background(), provider, []deadCredentialCandidate{{
		credentialRef:     "ref-a",
		apiKey:            "key-a",
		proxyURL:          "http://proxy-a",
		baseURL:           "https://upstream.example/v1",
		policyFingerprint: policyFingerprint,
	}})
	if errRemove != nil {
		t.Fatalf("removeDeadCredentialBatch() error = %v", errRemove)
	}
	if removed != 1 || backupDir == "" {
		t.Fatalf("removed = %d, backupDir = %q, want one removal and backup", removed, backupDir)
	}

	loaded, errLoad := config.LoadConfig(configPath)
	if errLoad != nil {
		t.Fatalf("LoadConfig() error = %v", errLoad)
	}
	entries := loaded.OpenAICompatibility[0].APIKeyEntries
	if len(entries) != 2 || entries[0].APIKey != "key-a" || entries[0].ProxyURL != "http://proxy-b" {
		t.Fatalf("remaining entries = %+v", entries)
	}
	summary, errRead := os.ReadFile(filepath.Join(backupDir, "removal-summary.json"))
	if errRead != nil {
		t.Fatalf("read removal summary: %v", errRead)
	}
	if strings.Contains(string(summary), "key-a") || !strings.Contains(string(summary), "ref-a") {
		t.Fatalf("removal summary leaked or omitted credential reference: %s", summary)
	}
}

func TestHandlerRemoveDeadCredentialBatchSkipsChangedPolicy(t *testing.T) {
	provider := util.OpenAICompatibleProviderKey("dead-test")
	deletePolicy := config.NormalizeOpenAICompatibilityCredentialPolicy(&config.OpenAICompatibilityCredentialPolicy{
		DeadCredential: &config.OpenAICompatibilityDeadCredentialPolicy{
			Enabled:       true,
			Statuses:      []int{http.StatusUnauthorized},
			Confirmations: 2,
			Action:        "delete",
		},
	})
	cfg := &config.Config{CredentialInFlight: config.DefaultCredentialInFlightConfig(), OpenAICompatibility: []config.OpenAICompatibility{{
		Name:             "dead-test",
		BaseURL:          "https://upstream.example/v1",
		CredentialPolicy: deletePolicy,
		APIKeyEntries:    []config.OpenAICompatibilityAPIKey{{APIKey: "key-a"}},
	}}}
	configPath := writeDeadCredentialTestConfig(t, cfg)
	h := &Handler{cfg: cfg, configFilePath: configPath}
	candidate := deadCredentialCandidate{
		providerKey:       provider,
		credentialRef:     "ref-a",
		apiKey:            "key-a",
		baseURL:           "https://upstream.example/v1",
		policyFingerprint: deadCredentialPolicyFingerprint(deletePolicy.DeadCredential),
	}

	// An administrator changes the policy after the candidate is queued but
	// before the worker reaches the config write. The stale candidate must not
	// delete a key under the old policy.
	cfg.OpenAICompatibility[0].CredentialPolicy = config.NormalizeOpenAICompatibilityCredentialPolicy(&config.OpenAICompatibilityCredentialPolicy{
		DeadCredential: &config.OpenAICompatibilityDeadCredentialPolicy{
			Enabled:  true,
			Statuses: []int{http.StatusUnauthorized},
			Action:   "dry-run",
		},
	})
	removed, backupDir, errRemove := h.removeDeadCredentialBatch(context.Background(), provider, []deadCredentialCandidate{candidate})
	if errRemove != nil {
		t.Fatalf("removeDeadCredentialBatch() error = %v", errRemove)
	}
	if removed != 0 || backupDir != "" {
		t.Fatalf("changed policy removal = (%d, %q), want no-op", removed, backupDir)
	}
	loaded, errLoad := config.LoadConfig(configPath)
	if errLoad != nil {
		t.Fatalf("LoadConfig() error = %v", errLoad)
	}
	if len(loaded.OpenAICompatibility) != 1 || len(loaded.OpenAICompatibility[0].APIKeyEntries) != 1 {
		t.Fatalf("stale candidate changed config: %+v", loaded.OpenAICompatibility)
	}
}

func TestDeadCredentialGroupSeparatesProviderEndpoints(t *testing.T) {
	left := deadCredentialCandidate{providerKey: "provider", baseURL: "https://one.example/v1"}
	right := deadCredentialCandidate{providerKey: "provider", baseURL: "https://two.example/v1"}
	if deadCredentialGroupKey(left) == deadCredentialGroupKey(right) {
		t.Fatal("candidates for different provider endpoints share a deletion group")
	}
	withSlash := deadCredentialCandidate{providerKey: "provider", baseURL: "https://one.example/v1/"}
	if deadCredentialGroupKey(left) != deadCredentialGroupKey(withSlash) {
		t.Fatal("equivalent trailing-slash endpoints did not share a deletion group")
	}
}

func TestDeadCredentialReaperDeletesAfterConfirmations(t *testing.T) {
	provider := util.OpenAICompatibleProviderKey("dead-test")
	policy := &config.OpenAICompatibilityCredentialPolicy{
		DeadCredential: &config.OpenAICompatibilityDeadCredentialPolicy{
			Enabled:       true,
			Statuses:      []int{http.StatusUnauthorized},
			Confirmations: 2,
			WindowSeconds: 60,
			Action:        "delete",
		},
	}
	cfg := &config.Config{
		CredentialInFlight: config.DefaultCredentialInFlightConfig(),
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:             "dead-test",
			BaseURL:          "https://upstream.example/v1",
			CredentialPolicy: policy,
			APIKeyEntries:    []config.OpenAICompatibilityAPIKey{{APIKey: "key-a"}},
		}},
	}
	cfg.OpenAICompatibility[0].CredentialPolicy = config.NormalizeOpenAICompatibilityCredentialPolicy(policy)
	configPath := writeDeadCredentialTestConfig(t, cfg)
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "dead-test-auth",
		Provider: provider,
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"api_key":      "key-a",
			"base_url":     "https://upstream.example/v1",
			"compat_name":  "dead-test",
			"provider_key": provider,
			"source":       "config:dead-test[test]",
		},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	h := NewHandler(cfg, configPath, manager)
	defer h.Close()

	failure := coreauth.Result{
		AuthID:   auth.ID,
		Provider: provider,
		Model:    "test-model",
		Error:    &coreauth.Error{HTTPStatus: http.StatusUnauthorized, Message: "authentication failed"},
	}
	manager.MarkResult(logging.WithRequestID(context.Background(), "same-request"), failure)
	manager.MarkResult(logging.WithRequestID(context.Background(), "same-request"), failure)
	time.Sleep(100 * time.Millisecond)
	beforeSecondRequest, errLoad := config.LoadConfig(configPath)
	if errLoad != nil {
		t.Fatalf("LoadConfig() before second request error = %v", errLoad)
	}
	if len(beforeSecondRequest.OpenAICompatibility) != 1 || len(beforeSecondRequest.OpenAICompatibility[0].APIKeyEntries) != 1 {
		t.Fatalf("same request counted twice; entries = %+v", beforeSecondRequest.OpenAICompatibility)
	}
	manager.MarkResult(logging.WithRequestID(context.Background(), "next-request"), failure)

	deadline := time.Now().Add(3 * time.Second)
	lastCount := -1
	lastErr := ""
	for time.Now().Before(deadline) {
		loaded, errLoad := config.LoadConfig(configPath)
		if errLoad != nil {
			lastErr = errLoad.Error()
		}
		if errLoad == nil && len(loaded.OpenAICompatibility) == 1 {
			lastCount = len(loaded.OpenAICompatibility[0].APIKeyEntries)
		}
		if errLoad == nil && len(loaded.OpenAICompatibility) == 1 && lastCount == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dead credential was not removed within confirmation window; last_count=%d last_error=%s", lastCount, lastErr)
}

func TestDeadCredentialReaperCancelsQueuedRemovalAfterSuccess(t *testing.T) {
	provider := util.OpenAICompatibleProviderKey("dead-test")
	cfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{{
		Name:    "dead-test",
		BaseURL: "https://upstream.example/v1",
		CredentialPolicy: config.NormalizeOpenAICompatibilityCredentialPolicy(&config.OpenAICompatibilityCredentialPolicy{
			DeadCredential: &config.OpenAICompatibilityDeadCredentialPolicy{
				Enabled:       true,
				Statuses:      []int{http.StatusUnauthorized},
				Confirmations: 2,
				Action:        "delete",
			},
		}),
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "key-a"}},
	}}}
	h := &Handler{cfg: cfg}
	reaper := &deadCredentialReaper{
		handler:       h,
		states:        make(map[string]deadCredentialState),
		pending:       make(map[string]deadCredentialCandidate),
		deleteHistory: make(map[string][]time.Time),
	}
	auth := &coreauth.Auth{
		ID:       "dead-test-auth",
		Provider: provider,
		Attributes: map[string]string{
			"api_key":      "key-a",
			"base_url":     "https://upstream.example/v1",
			"compat_name":  "dead-test",
			"provider_key": provider,
			"source":       "config:dead-test[test]",
		},
	}
	failure := coreauth.Result{AuthID: auth.ID, Error: &coreauth.Error{HTTPStatus: http.StatusUnauthorized, Message: "authentication failed"}}
	reaper.observeResult(context.Background(), failure, auth)
	reaper.observeResult(context.Background(), failure, auth)
	reaper.mu.Lock()
	if len(reaper.pending) != 1 {
		reaper.mu.Unlock()
		t.Fatalf("pending candidates = %d, want 1", len(reaper.pending))
	}
	reaper.mu.Unlock()

	reaper.observeResult(context.Background(), coreauth.Result{AuthID: auth.ID, Success: true}, auth)
	reaper.mu.Lock()
	defer reaper.mu.Unlock()
	if len(reaper.pending) != 0 || len(reaper.states) != 0 {
		t.Fatalf("success did not cancel pending dead-key state: pending=%d states=%d", len(reaper.pending), len(reaper.states))
	}
}

func TestDeadCredentialReaperDryRunNeverRemoves(t *testing.T) {
	provider := util.OpenAICompatibleProviderKey("dry-run-test")
	cfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{{
		Name:    "dry-run-test",
		BaseURL: "https://upstream.example/v1",
		CredentialPolicy: config.NormalizeOpenAICompatibilityCredentialPolicy(&config.OpenAICompatibilityCredentialPolicy{
			DeadCredential: &config.OpenAICompatibilityDeadCredentialPolicy{
				Enabled:       true,
				Statuses:      []int{http.StatusUnauthorized},
				Confirmations: 2,
				Action:        "dry-run",
			},
		}),
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "key-a"}},
	}}}
	h := &Handler{cfg: cfg}
	reaper := &deadCredentialReaper{
		handler:       h,
		states:        make(map[string]deadCredentialState),
		pending:       make(map[string]deadCredentialCandidate),
		deleteHistory: make(map[string][]time.Time),
	}
	auth := &coreauth.Auth{
		ID:       "dry-run-auth",
		Provider: provider,
		Attributes: map[string]string{
			"api_key":      "key-a",
			"base_url":     "https://upstream.example/v1",
			"compat_name":  "dry-run-test",
			"provider_key": provider,
			"source":       "config:dry-run-test[test]",
		},
	}
	failure := coreauth.Result{AuthID: auth.ID, Error: &coreauth.Error{HTTPStatus: http.StatusUnauthorized, Message: "authentication failed"}}
	reaper.observeResult(context.Background(), failure, auth)
	reaper.observeResult(context.Background(), failure, auth)
	reaper.mu.Lock()
	defer reaper.mu.Unlock()
	if len(reaper.pending) != 0 {
		t.Fatalf("dry-run queued deletion candidates = %d, want 0", len(reaper.pending))
	}
	if len(cfg.OpenAICompatibility[0].APIKeyEntries) != 1 {
		t.Fatalf("dry-run changed config entries: %+v", cfg.OpenAICompatibility[0].APIKeyEntries)
	}
}

func writeDeadCredentialTestConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data, errMarshal := yaml.Marshal(cfg)
	if errMarshal != nil {
		t.Fatalf("marshal test config: %v", errMarshal)
	}
	if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
		t.Fatalf("write test config: %v", errWrite)
	}
	return path
}
