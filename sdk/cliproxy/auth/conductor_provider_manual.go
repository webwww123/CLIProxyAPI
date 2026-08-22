package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
)

// ProviderCredentialManualTestOptions selects one auth or every cooling auth
// for an OpenAI-compatible provider.
type ProviderCredentialManualTestOptions struct {
	Provider string
	AuthIDs  []string
	Model    string
}

// ProviderCredentialManualTestResult reports a bounded direct credential test
// without exposing the raw credential value or upstream response body.
type ProviderCredentialManualTestResult struct {
	AuthID        string `json:"-"`
	Provider      string `json:"provider"`
	CredentialRef string `json:"credential_ref"`
	Model         string `json:"model,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	Success       bool   `json:"success"`
	Recovered     bool   `json:"recovered"`
	State         string `json:"state"`
	ErrorCode     string `json:"error_code,omitempty"`
}

type providerCredentialManualTestCandidate struct {
	auth         *Auth
	updatedAt    time.Time
	deadline     time.Time
	backoffLevel int
}

func resolveOpenAICompatProviderEntry(cfg *internalconfig.Config, provider string) (string, *internalconfig.OpenAICompatibility) {
	if cfg == nil {
		return "", nil
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return "", nil
	}
	for i := range cfg.OpenAICompatibility {
		entry := &cfg.OpenAICompatibility[i]
		if entry.Disabled {
			continue
		}
		providerKey := util.OpenAICompatibleProviderKey(entry.Name)
		if provider == providerKey || strings.EqualFold(provider, strings.TrimSpace(entry.Name)) {
			return providerKey, entry
		}
	}
	return "", nil
}

// ProviderCredentialPolicyStatuses lists retained policy state, optionally
// restricted to one provider name or provider key.
func (m *Manager) ProviderCredentialPolicyStatuses(provider string) ([]ProviderCredentialPolicyStatus, error) {
	if m == nil {
		return nil, fmt.Errorf("auth manager is nil")
	}
	providerKey := ""
	if strings.TrimSpace(provider) != "" {
		var entry *internalconfig.OpenAICompatibility
		providerKey, entry = resolveOpenAICompatProviderEntry(m.runtimeConfigSnapshot(), provider)
		if entry == nil || entry.CredentialPolicy == nil {
			return nil, fmt.Errorf("provider credential policy not found")
		}
	}

	now := time.Now()
	m.mu.RLock()
	statuses := make([]ProviderCredentialPolicyStatus, 0)
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		if providerKey != "" && !strings.EqualFold(executorKeyFromAuth(auth), providerKey) {
			continue
		}
		if status, ok := ProviderCredentialPolicyStatusForAuth(auth, now); ok {
			statuses = append(statuses, status)
		}
	}
	m.mu.RUnlock()
	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].State != statuses[j].State {
			return statuses[i].State == "cooling"
		}
		return statuses[i].CredentialRef < statuses[j].CredentialRef
	})
	return statuses, nil
}

// TestCoolingProviderCredentials directly tests cooling credentials through
// their registered executor. Failures never mutate penalty state.
func (m *Manager) TestCoolingProviderCredentials(ctx context.Context, opts ProviderCredentialManualTestOptions) ([]ProviderCredentialManualTestResult, error) {
	if m == nil {
		return nil, fmt.Errorf("auth manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	providerKey, entry := resolveOpenAICompatProviderEntry(m.runtimeConfigSnapshot(), opts.Provider)
	if entry == nil || entry.CredentialPolicy == nil {
		return nil, fmt.Errorf("provider credential policy not found")
	}
	policy := cloneProviderCredentialPolicy(entry.CredentialPolicy)
	models := providerCredentialManualTestModels(entry, opts.Model, policy.ManualTestMaxModels)
	if len(models) == 0 {
		return nil, fmt.Errorf("no eligible configured chat model found")
	}

	requestedIDs := make(map[string]struct{}, len(opts.AuthIDs))
	for _, authID := range opts.AuthIDs {
		if authID = strings.TrimSpace(authID); authID != "" {
			requestedIDs[authID] = struct{}{}
		}
	}
	now := time.Now()
	m.mu.RLock()
	candidates := make([]providerCredentialManualTestCandidate, 0)
	for _, auth := range m.auths {
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled || !strings.EqualFold(executorKeyFromAuth(auth), providerKey) {
			continue
		}
		if len(requestedIDs) > 0 {
			if _, ok := requestedIDs[auth.ID]; !ok {
				continue
			}
		}
		if !hasProviderCredentialPolicyState(auth) || !credentialWideQuotaActive(auth, now) {
			continue
		}
		candidates = append(candidates, providerCredentialManualTestCandidate{
			auth:         auth.Clone(),
			updatedAt:    auth.UpdatedAt,
			deadline:     credentialWideQuotaDeadline(auth),
			backoffLevel: auth.Quota.BackoffLevel,
		})
	}
	m.mu.RUnlock()
	if len(candidates) == 0 {
		return []ProviderCredentialManualTestResult{}, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return stableCredentialRef(candidates[i].auth) < stableCredentialRef(candidates[j].auth)
	})

	concurrency := policy.ManualTestConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	results := make([]ProviderCredentialManualTestResult, len(candidates))
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results[index] = providerCredentialManualCanceledResult(candidates[index], providerKey)
				return
			}
			results[index] = m.testCoolingProviderCredential(ctx, providerKey, policy, candidates[index], models)
		}(i)
	}
	wg.Wait()
	return results, nil
}

func providerCredentialManualTestModels(entry *internalconfig.OpenAICompatibility, requested string, maximum int) []string {
	if entry == nil {
		return nil
	}
	requested = strings.TrimSpace(requested)
	if maximum <= 0 {
		maximum = 3
	}
	models := make([]string, 0, maximum)
	seen := make(map[string]struct{})
	for _, model := range entry.Models {
		if model.Image {
			continue
		}
		name := strings.TrimSpace(model.Name)
		alias := strings.TrimSpace(model.Alias)
		if name == "" {
			name = alias
		}
		if name == "" {
			continue
		}
		if requested != "" && !strings.EqualFold(requested, name) && !strings.EqualFold(requested, alias) {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		models = append(models, name)
		if requested != "" || len(models) >= maximum {
			break
		}
	}
	return models
}

func (m *Manager) testCoolingProviderCredential(ctx context.Context, providerKey string, policy internalconfig.OpenAICompatibilityCredentialPolicy, candidate providerCredentialManualTestCandidate, models []string) ProviderCredentialManualTestResult {
	result := ProviderCredentialManualTestResult{
		AuthID:        candidate.auth.ID,
		Provider:      providerKey,
		CredentialRef: stableCredentialRef(candidate.auth),
		State:         "cooling",
	}
	if !m.reserveProviderCredentialManualTest(candidate.auth.ID) {
		result.ErrorCode = "test_in_progress"
		return result
	}
	defer m.releaseProviderCredentialManualTest(candidate.auth.ID)

	m.mu.RLock()
	executor := m.executors[executorKeyFromAuth(candidate.auth)]
	m.mu.RUnlock()
	if executor == nil {
		result.ErrorCode = "executor_unavailable"
		return result
	}

	timeout := time.Duration(policy.ManualTestTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, model := range models {
		result.Model = model
		payload, errMarshal := json.Marshal(map[string]any{
			"model": model,
			"messages": []map[string]string{{
				"role":    "user",
				"content": "ping",
			}},
			"max_tokens": 1,
			"stream":     false,
		})
		if errMarshal != nil {
			result.ErrorCode = "request_build_failed"
			break
		}
		response, errExecute := executor.Execute(testCtx, candidate.auth, cliproxyexecutor.Request{Model: model, Payload: payload}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
		if errExecute == nil {
			errExecute = validateProviderCredentialProbeResponse(response.Payload)
		}
		if errExecute == nil {
			result.Success = true
			result.HTTPStatus = http.StatusOK
			result.Recovered, result.State = m.finishProviderCredentialManualSuccess(testCtx, candidate)
			m.logProviderCredentialManualTest(result)
			return result
		}

		result.HTTPStatus = statusCodeFromError(errExecute)
		result.ErrorCode = providerCredentialManualErrorCode(testCtx, errExecute, result.HTTPStatus)
		if result.HTTPStatus == http.StatusUnauthorized || result.HTTPStatus == http.StatusPaymentRequired {
			break
		}
		if _, matched := providerCredentialPolicyMatch(&policy, errExecute); matched {
			break
		}
	}
	if current, ok := m.GetByID(candidate.auth.ID); ok {
		if status, hasStatus := ProviderCredentialPolicyStatusForAuth(current, time.Now()); hasStatus {
			result.State = status.State
		}
	}
	m.logProviderCredentialManualTest(result)
	return result
}

func providerCredentialManualCanceledResult(candidate providerCredentialManualTestCandidate, provider string) ProviderCredentialManualTestResult {
	return ProviderCredentialManualTestResult{
		AuthID:        candidate.auth.ID,
		Provider:      provider,
		CredentialRef: stableCredentialRef(candidate.auth),
		State:         "cooling",
		ErrorCode:     "canceled",
	}
}

func providerCredentialManualErrorCode(ctx context.Context, err error, status int) string {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if status == http.StatusUnauthorized || status == http.StatusPaymentRequired {
		return "credential_rejected"
	}
	if status > 0 {
		return "upstream_error"
	}
	return "invalid_response"
}

func (m *Manager) finishProviderCredentialManualSuccess(ctx context.Context, candidate providerCredentialManualTestCandidate) (bool, string) {
	now := time.Now()
	var snapshot *Auth
	m.mu.Lock()
	auth := m.auths[candidate.auth.ID]
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled || !hasProviderCredentialPolicyState(auth) ||
		!auth.UpdatedAt.Equal(candidate.updatedAt) || !credentialWideQuotaDeadline(auth).Equal(candidate.deadline) || auth.Quota.BackoffLevel != candidate.backoffLevel ||
		providerCredentialPolicyForAuthConfig(m.runtimeConfigSnapshot(), auth) == nil {
		m.mu.Unlock()
		return false, "stale"
	}
	if !recoverProviderCredentialPolicyState(auth, now) {
		m.mu.Unlock()
		return false, "stale"
	}
	_ = m.persist(ctx, auth)
	snapshot = auth.Clone()
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	m.persistCooldownStates(context.Background())
	return true, "active"
}

func (m *Manager) reserveProviderCredentialManualTest(authID string) bool {
	if m == nil || strings.TrimSpace(authID) == "" {
		return false
	}
	m.credentialManualTestMu.Lock()
	defer m.credentialManualTestMu.Unlock()
	if m.credentialManualTestInFlight == nil {
		m.credentialManualTestInFlight = make(map[string]struct{})
	}
	if _, exists := m.credentialManualTestInFlight[authID]; exists {
		return false
	}
	m.credentialManualTestInFlight[authID] = struct{}{}
	return true
}

func (m *Manager) releaseProviderCredentialManualTest(authID string) {
	if m == nil {
		return
	}
	m.credentialManualTestMu.Lock()
	delete(m.credentialManualTestInFlight, authID)
	m.credentialManualTestMu.Unlock()
}

func (m *Manager) logProviderCredentialManualTest(result ProviderCredentialManualTestResult) {
	fields := log.Fields{
		"provider":       result.Provider,
		"credential_ref": result.CredentialRef,
		"model":          result.Model,
		"status":         result.HTTPStatus,
		"state":          result.State,
		"recovered":      result.Recovered,
	}
	if result.Success {
		log.WithFields(fields).Infof(
			"manual provider credential test succeeded: credential_ref=%s model=%s recovered=%t state=%s",
			result.CredentialRef,
			result.Model,
			result.Recovered,
			result.State,
		)
		return
	}
	fields["error_code"] = result.ErrorCode
	log.WithFields(fields).Warnf(
		"manual provider credential test failed without penalty: credential_ref=%s model=%s status=%d error_code=%s state=%s",
		result.CredentialRef,
		result.Model,
		result.HTTPStatus,
		result.ErrorCode,
		result.State,
	)
}
