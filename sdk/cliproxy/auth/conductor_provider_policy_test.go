package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type providerCredentialPolicyExecutor struct {
	provider       string
	mu             sync.Mutex
	calls          []string
	models         []string
	failureStatus  int
	failureText    string
	succeedOnCall  int
	executeDone    chan struct{}
	executeRelease <-chan struct{}
	executeOnce    sync.Once
	probeErr       error
	probeDone      chan struct{}
	probeRelease   <-chan struct{}
	probeOnce      sync.Once
}

func (e *providerCredentialPolicyExecutor) Identifier() string { return e.provider }

func (e *providerCredentialPolicyExecutor) recordAttempt(auth *Auth) (callCount, succeedOnCall, failureStatus int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if auth != nil {
		e.calls = append(e.calls, auth.ID)
	}
	return len(e.calls), e.succeedOnCall, e.failureStatus
}

func (e *providerCredentialPolicyExecutor) Execute(_ context.Context, auth *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if req.Model == "probe-model" {
		e.probeOnce.Do(func() {
			if e.probeDone != nil {
				close(e.probeDone)
			}
		})
		if e.probeRelease != nil {
			<-e.probeRelease
		}
		if e.probeErr != nil {
			return cliproxyexecutor.Response{}, e.probeErr
		}
		return cliproxyexecutor.Response{Payload: []byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)}, nil
	}
	e.executeOnce.Do(func() {
		if e.executeDone != nil {
			close(e.executeDone)
		}
	})
	if e.executeRelease != nil {
		<-e.executeRelease
	}
	e.mu.Lock()
	e.models = append(e.models, req.Model)
	e.mu.Unlock()
	callCount, succeedOnCall, failureStatus := e.recordAttempt(auth)
	if succeedOnCall > 0 && callCount == succeedOnCall {
		return cliproxyexecutor.Response{Payload: []byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)}, nil
	}
	if failureStatus == 0 {
		failureStatus = http.StatusPaymentRequired
	}
	failureText := e.failureText
	if failureText == "" {
		failureText = "credential rejected"
	}
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: failureStatus, Message: failureText}
}

func (e *providerCredentialPolicyExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	callCount, succeedOnCall, status := e.recordAttempt(auth)
	if succeedOnCall > 0 && callCount == succeedOnCall {
		chunks := make(chan cliproxyexecutor.StreamChunk, 1)
		chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n")}
		close(chunks)
		return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
	}
	if status == 0 {
		status = http.StatusPaymentRequired
	}
	return nil, &Error{HTTPStatus: status, Message: "credential rejected"}
}

func (e *providerCredentialPolicyExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *providerCredentialPolicyExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}

func (e *providerCredentialPolicyExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *providerCredentialPolicyExecutor) Calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

func (e *providerCredentialPolicyExecutor) Models() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.models...)
}

func newProviderCredentialPolicyManager(t *testing.T, maxRetryCredentials int, policy *internalconfig.OpenAICompatibilityCredentialPolicy, executor *providerCredentialPolicyExecutor, authCount int) (*Manager, []string) {
	t.Helper()
	provider := util.OpenAICompatibleProviderKey("mistral")
	executor.provider = provider
	maxRetry := maxRetryCredentials
	disableCooling := false
	cfg := &internalconfig.Config{OpenAICompatibility: []internalconfig.OpenAICompatibility{{
		Name:                "mistral",
		BaseURL:             "https://api.mistral.ai/v1",
		DisableCooling:      &disableCooling,
		MaxRetryCredentials: &maxRetry,
		CredentialPolicy:    policy,
		Models: []internalconfig.OpenAICompatibilityModel{{
			Name:  "upstream-model",
			Alias: "test-model",
		}},
	}}}
	cfg.SanitizeOpenAICompatibility()
	m := NewManager(nil, nil, nil)
	m.SetConfig(cfg)
	m.SetRetryConfig(0, 0, 1)
	m.RegisterExecutor(executor)

	ids := make([]string, 0, authCount)
	reg := registry.GetGlobalRegistry()
	for i := 0; i < authCount; i++ {
		id := "provider-policy-auth-" + string(rune('a'+i))
		auth := &Auth{
			ID:       id,
			Provider: provider,
			Status:   StatusActive,
			Attributes: map[string]string{
				AttributeConfigIndex: "0",
				"compat_name":        "mistral",
				"provider_key":       provider,
				"source":             "config:mistral[test]",
			},
		}
		reg.RegisterClient(id, provider, []*registry.ModelInfo{{ID: "test-model"}, {ID: "probe-model"}})
		if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", id, errRegister)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			reg.UnregisterClient(id)
		}
		m.StopAutoRefresh()
	})
	return m, ids
}

func TestProviderCredentialPolicy_MaxRetryAndImmediateCredentialCooldown(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusPaymentRequired} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
				ScopeStatuses:          []int{http.StatusUnauthorized, http.StatusPaymentRequired},
				InitialCooldownSeconds: 60,
				MaxCooldownSeconds:     3600,
				BackoffFactor:          2,
			}
			executor := &providerCredentialPolicyExecutor{failureStatus: status}
			m, _ := newProviderCredentialPolicyManager(t, 2, policy, executor, 3)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, errExecute := m.Execute(ctx, []string{executor.provider}, cliproxyexecutor.Request{Model: "test-model"}, cliproxyexecutor.Options{})
			if errExecute == nil {
				t.Fatal("Execute() error = nil")
			}
			calls := executor.Calls()
			if len(calls) != 2 {
				t.Fatalf("credential calls = %v, want exactly 2", calls)
			}
			for _, id := range calls {
				updated, ok := m.GetByID(id)
				if !ok || updated == nil {
					t.Fatalf("GetByID(%s) missing", id)
				}
				if !updated.Unavailable || !updated.Quota.Exceeded || updated.Quota.Reason != providerCredentialPolicyQuotaReason {
					t.Fatalf("auth %s policy state = %+v", id, updated)
				}
				if !updated.NextRetryAfter.After(time.Now()) || updated.Quota.BackoffLevel != 1 {
					t.Fatalf("auth %s cooldown = %+v", id, updated.Quota)
				}
				if state := updated.ModelStates["test-model"]; state != nil {
					t.Fatalf("auth %s received model-only state: %+v", id, state)
				}
			}
		})
	}
}

func TestProviderCredentialPolicy_FourCredentialImmediateFailover(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 60,
		MaxCooldownSeconds:     3600,
		BackoffFactor:          2,
	}
	executor := &providerCredentialPolicyExecutor{failureStatus: http.StatusPaymentRequired, succeedOnCall: 4}
	m, _ := newProviderCredentialPolicyManager(t, 4, policy, executor, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, errExecute := m.Execute(ctx, []string{executor.provider}, cliproxyexecutor.Request{Model: "test-model"}, cliproxyexecutor.Options{}); errExecute != nil {
		t.Fatalf("Execute() error = %v, want fourth credential success", errExecute)
	}
	if calls := executor.Calls(); len(calls) != 4 {
		t.Fatalf("credential calls = %v, want exactly 4", calls)
	}
}

func TestProviderCredentialPolicy_FourCredentialImmediateStreamFailover(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 60,
		MaxCooldownSeconds:     3600,
		BackoffFactor:          2,
	}
	executor := &providerCredentialPolicyExecutor{failureStatus: http.StatusPaymentRequired, succeedOnCall: 4}
	m, _ := newProviderCredentialPolicyManager(t, 4, policy, executor, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result, errExecute := m.ExecuteStream(ctx, []string{executor.provider}, cliproxyexecutor.Request{Model: "test-model"}, cliproxyexecutor.Options{Stream: true})
	if errExecute != nil {
		t.Fatalf("ExecuteStream() error = %v, want fourth credential success", errExecute)
	}
	if result == nil || result.Chunks == nil {
		t.Fatal("ExecuteStream() returned no chunks")
	}
	for range result.Chunks {
	}
	if calls := executor.Calls(); len(calls) != 4 {
		t.Fatalf("stream credential calls = %v, want exactly 4", calls)
	}
}

func TestProviderCredentialPolicy_PersistsCredentialWideCooldown(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 60,
		MaxCooldownSeconds:     3600,
		BackoffFactor:          2,
	}
	executor := &providerCredentialPolicyExecutor{failureStatus: http.StatusPaymentRequired}
	m, _ := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
	store := &recordingCooldownStateStore{}
	m.SetCooldownStateStore(store)

	_, _ = m.Execute(context.Background(), []string{executor.provider}, cliproxyexecutor.Request{Model: "test-model"}, cliproxyexecutor.Options{})
	store.mu.Lock()
	records := cloneCooldownStateRecords(store.records)
	store.mu.Unlock()
	if len(records) != 1 {
		t.Fatalf("persisted cooldown records = %+v, want one auth-wide record", records)
	}
	record := records[0]
	if record.Model != "" || record.Quota.Reason != providerCredentialPolicyQuotaReason || record.Quota.BackoffLevel != 1 {
		t.Fatalf("persisted cooldown record = %+v", record)
	}
	if record.LastError == nil || record.LastError.HTTPStatus != http.StatusPaymentRequired || record.LastError.Message != "provider credential policy failure" {
		t.Fatalf("persisted error was not structurally sanitized: %+v", record.LastError)
	}
	firstRetry := record.NextRetryAfter
	firstSaveCount := store.saveCount.Load()
	m.MarkResult(context.Background(), Result{
		AuthID:          record.AuthID,
		Provider:        executor.provider,
		Model:           "test-model",
		Success:         false,
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusPaymentRequired, Message: "duplicate in-flight failure"},
	})
	updated, _ := m.GetByID(record.AuthID)
	if updated == nil || !updated.NextRetryAfter.Equal(firstRetry) || updated.Quota.BackoffLevel != 1 {
		t.Fatalf("duplicate in-window failure changed cooldown: %+v", updated)
	}
	if got := store.saveCount.Load(); got != firstSaveCount {
		t.Fatalf("duplicate in-window failure persisted cooldown %d times, want %d", got, firstSaveCount)
	}
}

func TestProviderCredentialPolicy_LogMessageContainsSafeDiagnostics(t *testing.T) {
	hook := setupTestLoggerHook(t)
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 60,
		MaxCooldownSeconds:     3600,
		BackoffFactor:          2,
	}
	executor := &providerCredentialPolicyExecutor{}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
	m.MarkResult(context.Background(), Result{
		AuthID:          ids[0],
		Provider:        executor.provider,
		Model:           "test-model",
		Success:         false,
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusPaymentRequired, Message: "sensitive upstream detail"},
	})

	entries := hook.AllEntries()
	if len(entries) == 0 {
		t.Fatal("credential policy warning was not logged")
	}
	message := entries[len(entries)-1].Message
	wantParts := []string{
		"provider credential policy cooldown applied",
		"credential_ref=" + stableCredentialRef(&Auth{ID: ids[0]}),
		"status=402",
		"cooldown=1m0s",
		"backoff_level=1",
	}
	for _, want := range wantParts {
		if !strings.Contains(message, want) {
			t.Fatalf("log message %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "sensitive upstream detail") || strings.Contains(message, ids[0]) {
		t.Fatalf("log message leaked sensitive or raw credential data: %q", message)
	}
}

func TestProviderCredentialPolicyCooldownBackoffAndWindowReuse(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		InitialCooldownSeconds: 2,
		MaxCooldownSeconds:     20,
		BackoffFactor:          3,
	}
	now := time.Unix(1_700_000_000, 0)
	next, level := providerCredentialPolicyCooldown(policy, QuotaState{}, now)
	if got := next.Sub(now); got != 2*time.Second || level != 1 {
		t.Fatalf("first cooldown = (%v, %d), want (2s, 1)", got, level)
	}
	next, level = providerCredentialPolicyCooldown(policy, QuotaState{BackoffLevel: level}, now)
	if got := next.Sub(now); got != 6*time.Second || level != 2 {
		t.Fatalf("second cooldown = (%v, %d), want (6s, 2)", got, level)
	}
	active := now.Add(9 * time.Second)
	next, reusedLevel := providerCredentialPolicyCooldown(policy, QuotaState{BackoffLevel: level, NextRecoverAt: active}, now)
	if !next.Equal(active) || reusedLevel != level {
		t.Fatalf("active window = (%v, %d), want (%v, %d)", next, reusedLevel, active, level)
	}
}

func TestProviderCredentialProbeRecoversAndRepenalizes(t *testing.T) {
	tests := []struct {
		name          string
		probeErr      error
		wantRecovered bool
	}{
		{name: "success", wantRecovered: true},
		{name: "failure", probeErr: &Error{HTTPStatus: http.StatusPaymentRequired, Message: "still exhausted"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
				ScopeStatuses:          []int{http.StatusPaymentRequired},
				InitialCooldownSeconds: 1,
				MaxCooldownSeconds:     30,
				BackoffFactor:          2,
				ProbeModel:             "probe-model",
				ProbeIntervalSeconds:   1,
				ProbeConcurrency:       1,
			}
			executor := &providerCredentialPolicyExecutor{probeErr: tt.probeErr, probeDone: make(chan struct{})}
			m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
			now := time.Now()
			m.mu.Lock()
			auth := m.auths[ids[0]]
			auth.Unavailable = true
			auth.Status = StatusError
			auth.StatusMessage = "credential policy cooldown"
			auth.NextRetryAfter = now.Add(-time.Second)
			auth.Quota = QuotaState{Exceeded: true, Reason: providerCredentialPolicyQuotaReason, NextRecoverAt: now.Add(-time.Second), BackoffLevel: 1}
			auth.LastError = &Error{HTTPStatus: http.StatusPaymentRequired, Message: "subscription exhausted"}
			m.mu.Unlock()

			m.scheduleProviderCredentialProbes(context.Background(), now)
			select {
			case <-executor.probeDone:
			case <-time.After(time.Second):
				t.Fatal("probe did not execute")
			}
			deadline := time.Now().Add(time.Second)
			for {
				updated, _ := m.GetByID(ids[0])
				if tt.wantRecovered {
					if updated != nil && !updated.Unavailable && !updated.Quota.Exceeded {
						break
					}
				} else if updated != nil && updated.Unavailable && updated.Quota.Reason == providerCredentialPolicyQuotaReason && updated.Quota.BackoffLevel == 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("probe result not applied: %+v", updated)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestProviderCredentialProbeRestoresExpiredStateAndRunsImmediately(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
		ProbeModel:             "probe-model",
		ProbeIntervalSeconds:   1,
		ProbeConcurrency:       1,
	}
	executor := &providerCredentialPolicyExecutor{probeDone: make(chan struct{})}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
	expired := time.Now().Add(-time.Minute)
	store := &recordingCooldownStateStore{load: []CooldownStateRecord{{
		Provider:       executor.provider,
		AuthID:         ids[0],
		NextRetryAfter: expired,
		Reason:         providerCredentialPolicyQuotaReason,
		Quota: QuotaState{
			Exceeded:      true,
			Reason:        providerCredentialPolicyQuotaReason,
			NextRecoverAt: expired,
			BackoffLevel:  1,
		},
		LastError: &Error{HTTPStatus: http.StatusPaymentRequired, Message: "subscription exhausted"},
		UpdatedAt: expired,
	}}}
	m.SetCooldownStateStore(store)
	if errRestore := m.RestoreCooldownStates(context.Background()); errRestore != nil {
		t.Fatalf("RestoreCooldownStates() error = %v", errRestore)
	}
	restored, _ := m.GetByID(ids[0])
	if restored == nil || !restored.Unavailable || !restored.NextRetryAfter.After(time.Now()) {
		t.Fatalf("restored credential was not fenced for probing: %+v", restored)
	}

	m.StartAutoRefresh(context.Background(), time.Hour)
	select {
	case <-executor.probeDone:
	case <-time.After(time.Second):
		t.Fatal("restored expired credential was not probed immediately")
	}
	deadline := time.Now().Add(time.Second)
	for {
		updated, _ := m.GetByID(ids[0])
		if updated != nil && !updated.Unavailable && !updated.Quota.Exceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restored credential did not recover after probe: %+v", updated)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProviderCredentialProbeLeaseSurvivesSuccessAndConfigRefresh(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
		ProbeModel:             "probe-model",
		ProbeIntervalSeconds:   1,
		ProbeConcurrency:       1,
	}
	probeRelease := make(chan struct{})
	executor := &providerCredentialPolicyExecutor{probeDone: make(chan struct{}), probeRelease: probeRelease}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
	now := time.Now()
	m.mu.Lock()
	auth := m.auths[ids[0]]
	auth.Unavailable = true
	auth.Status = StatusError
	auth.NextRetryAfter = now.Add(100 * time.Millisecond)
	auth.Quota = QuotaState{Exceeded: true, Reason: providerCredentialPolicyQuotaReason, NextRecoverAt: auth.NextRetryAfter, BackoffLevel: 1}
	auth.LastError = &Error{HTTPStatus: http.StatusPaymentRequired, Message: "subscription exhausted"}
	m.mu.Unlock()

	m.scheduleProviderCredentialProbes(context.Background(), now)
	select {
	case <-executor.probeDone:
	case <-time.After(time.Second):
		t.Fatal("scheduled credential probe did not start")
	}

	m.MarkResult(context.Background(), Result{AuthID: ids[0], Provider: executor.provider, Model: "test-model", Success: true})
	afterSuccess, _ := m.GetByID(ids[0])
	if afterSuccess == nil || !afterSuccess.Unavailable || !afterSuccess.Quota.Exceeded || !afterSuccess.NextRetryAfter.After(time.Now()) {
		t.Fatalf("in-flight success cleared the probe lease: %+v", afterSuccess)
	}

	incoming := &Auth{
		ID:       ids[0],
		Provider: executor.provider,
		Status:   StatusActive,
		Attributes: map[string]string{
			AttributeConfigIndex: "0",
			"compat_name":        "mistral",
			"provider_key":       executor.provider,
		},
	}
	if _, errUpdate := m.Update(WithSkipPersist(context.Background()), incoming); errUpdate != nil {
		t.Fatalf("Update() error = %v", errUpdate)
	}
	afterUpdate, _ := m.GetByID(ids[0])
	if afterUpdate == nil || !afterUpdate.Unavailable || !afterUpdate.Quota.Exceeded || !afterUpdate.NextRetryAfter.After(time.Now()) {
		t.Fatalf("config refresh cleared the probe lease: %+v", afterUpdate)
	}

	close(probeRelease)
	deadline := time.Now().Add(time.Second)
	for {
		updated, _ := m.GetByID(ids[0])
		if updated != nil && !updated.Unavailable && !updated.Quota.Exceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("credential did not recover after releasing probe: %+v", updated)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProviderCredentialProbeLeaseHeartbeatExtendsFence(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:        []int{http.StatusPaymentRequired},
		ProbeModel:           "probe-model",
		ProbeIntervalSeconds: 1,
		ProbeConcurrency:     1,
	}
	executor := &providerCredentialPolicyExecutor{}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
	now := time.Now()
	originalRecovery := now.Add(-time.Second)
	originalLease := now.Add(time.Second)
	m.mu.Lock()
	auth := m.auths[ids[0]]
	auth.Unavailable = true
	auth.Status = StatusError
	auth.NextRetryAfter = originalLease
	auth.Quota = QuotaState{Exceeded: true, Reason: providerCredentialPolicyQuotaReason, NextRecoverAt: originalRecovery, BackoffLevel: 1}
	m.mu.Unlock()

	if !m.extendProviderCredentialProbeLease(ids[0], now.Add(2*time.Second)) {
		t.Fatal("extendProviderCredentialProbeLease() = false, want true")
	}
	updated, _ := m.GetByID(ids[0])
	if updated == nil || !updated.NextRetryAfter.After(originalLease) {
		t.Fatalf("probe lease was not extended: %+v", updated)
	}
	if !updated.Quota.NextRecoverAt.Equal(originalRecovery) {
		t.Fatalf("probe heartbeat changed original recovery deadline: got %v want %v", updated.Quota.NextRecoverAt, originalRecovery)
	}
}

func TestProviderCredentialProbePolicyRemovalClearsStaleResult(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
		ProbeModel:             "probe-model",
		ProbeIntervalSeconds:   1,
		ProbeConcurrency:       1,
	}
	probeRelease := make(chan struct{})
	executor := &providerCredentialPolicyExecutor{
		probeErr:     &Error{HTTPStatus: http.StatusPaymentRequired, Message: "still exhausted"},
		probeDone:    make(chan struct{}),
		probeRelease: probeRelease,
	}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
	now := time.Now()
	m.mu.Lock()
	auth := m.auths[ids[0]]
	auth.Unavailable = true
	auth.Status = StatusError
	auth.NextRetryAfter = now.Add(-time.Second)
	auth.Quota = QuotaState{Exceeded: true, Reason: providerCredentialPolicyQuotaReason, NextRecoverAt: auth.NextRetryAfter, BackoffLevel: 1}
	m.mu.Unlock()

	m.scheduleProviderCredentialProbes(context.Background(), now)
	select {
	case <-executor.probeDone:
	case <-time.After(time.Second):
		t.Fatal("credential probe did not start")
	}
	cfg := m.runtimeConfigSnapshot().CloneForRuntime()
	cfg.OpenAICompatibility[0].CredentialPolicy = nil
	m.SetConfig(cfg)
	close(probeRelease)

	deadline := time.Now().Add(time.Second)
	for {
		updated, _ := m.GetByID(ids[0])
		if updated != nil && !updated.Unavailable && !updated.Quota.Exceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("removed policy retained stale probe penalty: %+v", updated)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProviderCredentialPolicyRuleOverrideAndDeterministicJitter(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusUnauthorized},
		InitialCooldownSeconds: 60,
		MaxCooldownSeconds:     600,
		BackoffFactor:          2,
		CooldownJitterPercent:  10,
		PenaltyRules: []internalconfig.OpenAICompatibilityCredentialPolicyRule{{
			Name:                   "subscription-exhausted",
			Status:                 http.StatusPaymentRequired,
			Match:                  []string{"check your subscription"},
			InitialCooldownSeconds: 3600,
			MaxCooldownSeconds:     10 * 24 * 60 * 60,
			BackoffFactor:          5,
		}},
	}
	penalty, matched := providerCredentialPolicyMatch(policy, &Error{HTTPStatus: http.StatusPaymentRequired, Message: "CHECK YOUR SUBSCRIPTION before retrying"})
	if !matched || penalty.rule != "subscription-exhausted" || penalty.initialCooldownSeconds != 3600 || penalty.backoffFactor != 5 {
		t.Fatalf("matched penalty = %+v, matched=%t", penalty, matched)
	}
	now := time.Unix(1_700_000_000, 0)
	nextA, levelA := providerCredentialPenaltyCooldown(penalty, QuotaState{}, now, "auth-a")
	nextARepeat, levelARepeat := providerCredentialPenaltyCooldown(penalty, QuotaState{}, now, "auth-a")
	if !nextA.Equal(nextARepeat) || levelA != levelARepeat {
		t.Fatalf("jitter is not deterministic: (%v,%d) vs (%v,%d)", nextA, levelA, nextARepeat, levelARepeat)
	}
	if got := nextA.Sub(now); got < 54*time.Minute || got > 66*time.Minute {
		t.Fatalf("jittered first cooldown = %v, want within +/-10%%", got)
	}
	nextB, _ := providerCredentialPenaltyCooldown(penalty, QuotaState{}, now, "auth-b")
	if nextA.Equal(nextB) {
		t.Fatalf("different credentials received identical deterministic jitter: %v", nextA)
	}
	maxNext, maxLevel := providerCredentialPenaltyCooldown(penalty, QuotaState{BackoffLevel: 20}, now, "auth-a")
	if got := maxNext.Sub(now); got > 10*24*time.Hour || got < 5*24*time.Hour {
		t.Fatalf("max jittered cooldown = %v, want <=10d and >=5d", got)
	}
	if maxLevel != 20 {
		t.Fatalf("max backoff level advanced: got %d want 20", maxLevel)
	}
}

func TestProviderCredentialPolicyRealSuccessClearsOnlyExpiredPenalty(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
	}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, &providerCredentialPolicyExecutor{}, 1)
	now := time.Now()
	m.mu.Lock()
	auth := m.auths[ids[0]]
	auth.Unavailable = true
	auth.Status = StatusError
	auth.NextRetryAfter = now.Add(time.Minute)
	auth.Quota = QuotaState{Exceeded: true, Reason: providerCredentialPolicyQuotaReason, NextRecoverAt: auth.NextRetryAfter, BackoffLevel: 3}
	auth.LastError = &Error{HTTPStatus: http.StatusPaymentRequired, Message: "provider credential policy failure"}
	auth.UpdatedAt = now
	m.mu.Unlock()

	m.MarkResult(context.Background(), Result{AuthID: ids[0], Model: "test-model", Success: true})
	active, _ := m.GetByID(ids[0])
	if active == nil || !active.Quota.Exceeded || active.Quota.BackoffLevel != 3 {
		t.Fatalf("active cooldown was cleared by stale success: %+v", active)
	}

	m.mu.Lock()
	auth = m.auths[ids[0]]
	auth.NextRetryAfter = now.Add(-time.Second)
	auth.Quota.NextRecoverAt = auth.NextRetryAfter
	m.mu.Unlock()
	m.MarkResult(context.Background(), Result{AuthID: ids[0], Model: "test-model", Success: true})
	recovered, _ := m.GetByID(ids[0])
	if recovered == nil || recovered.Quota.Exceeded || recovered.Quota.Reason != providerCredentialPolicyQuotaReason || recovered.Quota.BackoffLevel != 3 || recovered.Unavailable {
		t.Fatalf("expired penalty was not cleared by real success: %+v", recovered)
	}
	healthyRecords := m.cooldownStateRecordsSnapshot()
	if len(healthyRecords) != 1 || healthyRecords[0].Status != "healthy" || healthyRecords[0].Quota.BackoffLevel != 3 || !healthyRecords[0].NextRetryAfter.IsZero() {
		t.Fatalf("healthy retained history snapshot = %+v", healthyRecords)
	}
	m.MarkResult(context.Background(), Result{
		AuthID:          ids[0],
		Model:           "test-model",
		Success:         false,
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusPaymentRequired, Message: "flapping again"},
	})
	repenalized, _ := m.GetByID(ids[0])
	if repenalized == nil || !repenalized.Quota.Exceeded || repenalized.Quota.BackoffLevel != 4 {
		t.Fatalf("post-success failure did not continue retained ladder: %+v", repenalized)
	}
}

func TestProviderCredentialPolicyExpiredHistoryPersistsRestoresEligibleAndEscalates(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
	}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, &providerCredentialPolicyExecutor{}, 1)
	expired := time.Now().Add(-time.Minute)
	m.mu.Lock()
	auth := m.auths[ids[0]]
	auth.Unavailable = true
	auth.Status = StatusError
	auth.NextRetryAfter = expired
	auth.Quota = QuotaState{Exceeded: true, Reason: providerCredentialPolicyQuotaReason, NextRecoverAt: expired, BackoffLevel: 2}
	auth.LastError = &Error{HTTPStatus: http.StatusPaymentRequired, Message: "provider credential policy failure"}
	auth.UpdatedAt = expired
	m.mu.Unlock()
	records := m.cooldownStateRecordsSnapshot()
	if len(records) != 1 || records[0].Status != "eligible" || records[0].Quota.BackoffLevel != 2 {
		t.Fatalf("expired history snapshot = %+v", records)
	}

	restoreStore := &recordingCooldownStateStore{load: cloneCooldownStateRecords(records)}
	restoredManager, restoredIDs := newProviderCredentialPolicyManager(t, 1, policy, &providerCredentialPolicyExecutor{}, 1)
	restoredManager.SetCooldownStateStore(restoreStore)
	if errRestore := restoredManager.RestoreCooldownStates(context.Background()); errRestore != nil {
		t.Fatalf("RestoreCooldownStates() error = %v", errRestore)
	}
	restored, _ := restoredManager.GetByID(restoredIDs[0])
	if restored == nil || restored.Unavailable || !restored.Quota.Exceeded || restored.Quota.BackoffLevel != 2 {
		t.Fatalf("restored expired history = %+v", restored)
	}
	if blocked, _, _ := isAuthBlockedForModel(restored, "test-model", time.Now()); blocked {
		t.Fatalf("restored expired credential was not immediately eligible: %+v", restored)
	}
	restoredManager.MarkResult(context.Background(), Result{
		AuthID:          restoredIDs[0],
		Model:           "test-model",
		Success:         false,
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusPaymentRequired, Message: "still exhausted"},
	})
	escalated, _ := restoredManager.GetByID(restoredIDs[0])
	if escalated == nil || !escalated.Unavailable || escalated.Quota.BackoffLevel != 3 || !escalated.NextRetryAfter.After(time.Now()) {
		t.Fatalf("restored penalty did not escalate: %+v", escalated)
	}
}

func TestProviderCredentialPolicyExpiredHistorySurvivesUnrelatedFailure(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
	}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, &providerCredentialPolicyExecutor{}, 1)
	expired := time.Now().Add(-time.Minute)
	setProviderCredentialPolicyTestState(m, ids[0], expired, 2)
	m.MarkResult(context.Background(), Result{
		AuthID:  ids[0],
		Model:   "test-model",
		Success: false,
		Error:   &Error{HTTPStatus: http.StatusBadGateway, Message: "temporary model path failure"},
	})
	updated, _ := m.GetByID(ids[0])
	if updated == nil || !updated.Quota.Exceeded || updated.Quota.Reason != providerCredentialPolicyQuotaReason || updated.Quota.BackoffLevel != 2 {
		t.Fatalf("unrelated failure erased penalty history: %+v", updated)
	}
	if credentialWideQuotaActive(updated, time.Now()) {
		t.Fatalf("unrelated model cooldown became an auth-wide policy cooldown: %+v", updated)
	}
	status, ok := ProviderCredentialPolicyStatusForAuth(updated, time.Now())
	if !ok || status.State != "eligible" || status.LastHTTPStatus != http.StatusPaymentRequired {
		t.Fatalf("retained policy status = %+v, ok=%t", status, ok)
	}
	if blocked, _, _ := isAuthBlockedForModel(updated, "sibling-model", time.Now()); blocked {
		t.Fatalf("unrelated model failure blocked sibling models via retained history: %+v", updated)
	}
	records := m.cooldownStateRecordsSnapshot()
	if len(records) == 0 || records[0].Status != "eligible" || records[0].Quota.BackoffLevel != 2 {
		t.Fatalf("retained history persistence = %+v", records)
	}
}

func TestProviderCredentialPolicyHealthyHistoryRestoresAcrossRestart(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
	}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, &providerCredentialPolicyExecutor{}, 1)
	setProviderCredentialPolicyTestState(m, ids[0], time.Now().Add(-time.Minute), 2)
	m.MarkResult(context.Background(), Result{AuthID: ids[0], Model: "test-model", Success: true})
	records := m.cooldownStateRecordsSnapshot()
	if len(records) != 1 || records[0].Status != "healthy" || records[0].Quota.Exceeded || records[0].Quota.BackoffLevel != 2 {
		t.Fatalf("healthy persisted records = %+v", records)
	}

	restoredManager, restoredIDs := newProviderCredentialPolicyManager(t, 1, policy, &providerCredentialPolicyExecutor{}, 1)
	restoredManager.SetCooldownStateStore(&recordingCooldownStateStore{load: cloneCooldownStateRecords(records)})
	if errRestore := restoredManager.RestoreCooldownStates(context.Background()); errRestore != nil {
		t.Fatalf("RestoreCooldownStates() error = %v", errRestore)
	}
	restored, _ := restoredManager.GetByID(restoredIDs[0])
	if restored == nil || restored.Quota.Exceeded || restored.Quota.Reason != providerCredentialPolicyQuotaReason || restored.Quota.BackoffLevel != 2 || restored.Unavailable {
		t.Fatalf("restored healthy history = %+v", restored)
	}
	status, ok := ProviderCredentialPolicyStatusForAuth(restored, time.Now())
	if !ok || status.State != "healthy" {
		t.Fatalf("restored healthy status = %+v, ok=%t", status, ok)
	}
	reset, _, errReset := restoredManager.ResetQuota(context.Background(), restoredIDs[0])
	if errReset != nil || reset == nil || reset.Quota.Reason != "" || reset.Quota.BackoffLevel != 0 {
		t.Fatalf("ResetQuota() did not fully clear healthy history: reset=%+v err=%v", reset, errReset)
	}
}

func TestProviderCredentialPolicyManualTestSuccessFailureAndFence(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:            []int{http.StatusUnauthorized, http.StatusPaymentRequired},
		InitialCooldownSeconds:   60,
		MaxCooldownSeconds:       3600,
		BackoffFactor:            2,
		ManualTestConcurrency:    2,
		ManualTestMaxModels:      3,
		ManualTestTimeoutSeconds: 5,
	}

	t.Run("success clears penalty", func(t *testing.T) {
		executor := &providerCredentialPolicyExecutor{succeedOnCall: 1}
		m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
		setProviderCredentialPolicyTestState(m, ids[0], time.Now().Add(time.Minute), 2)
		results, errTest := m.TestCoolingProviderCredentials(context.Background(), ProviderCredentialManualTestOptions{Provider: "mistral", AuthIDs: ids, Model: "test-model"})
		if errTest != nil || len(results) != 1 || !results[0].Success || !results[0].Recovered || results[0].State != "active" {
			t.Fatalf("manual success results = %+v, err=%v", results, errTest)
		}
		updated, _ := m.GetByID(ids[0])
		if updated == nil || updated.Quota.Exceeded || updated.Quota.Reason != "" || updated.Quota.BackoffLevel != 0 || updated.Unavailable {
			t.Fatalf("manual success did not clear penalty: %+v", updated)
		}
		if models := executor.Models(); len(models) != 1 || models[0] != "upstream-model" {
			t.Fatalf("manual test models = %v, want configured upstream model", models)
		}
	})

	t.Run("failure leaves penalty unchanged", func(t *testing.T) {
		executor := &providerCredentialPolicyExecutor{failureStatus: http.StatusPaymentRequired}
		m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
		deadline := time.Now().Add(time.Minute)
		setProviderCredentialPolicyTestState(m, ids[0], deadline, 2)
		results, errTest := m.TestCoolingProviderCredentials(context.Background(), ProviderCredentialManualTestOptions{Provider: "mistral", AuthIDs: ids})
		if errTest != nil || len(results) != 1 || results[0].Success || results[0].Recovered || results[0].ErrorCode != "credential_rejected" {
			t.Fatalf("manual failure results = %+v, err=%v", results, errTest)
		}
		updated, _ := m.GetByID(ids[0])
		if updated == nil || !credentialWideQuotaDeadline(updated).Equal(deadline) || updated.Quota.BackoffLevel != 2 {
			t.Fatalf("manual failure changed penalty: %+v", updated)
		}
	})

	t.Run("stale success cannot erase newer failure", func(t *testing.T) {
		release := make(chan struct{})
		executor := &providerCredentialPolicyExecutor{succeedOnCall: 1, executeDone: make(chan struct{}), executeRelease: release}
		m, ids := newProviderCredentialPolicyManager(t, 1, policy, executor, 1)
		setProviderCredentialPolicyTestState(m, ids[0], time.Now().Add(time.Minute), 2)
		resultCh := make(chan []ProviderCredentialManualTestResult, 1)
		go func() {
			results, _ := m.TestCoolingProviderCredentials(context.Background(), ProviderCredentialManualTestOptions{Provider: "mistral", AuthIDs: ids})
			resultCh <- results
		}()
		select {
		case <-executor.executeDone:
		case <-time.After(time.Second):
			t.Fatal("manual credential test did not start")
		}
		newDeadline := time.Now().Add(2 * time.Hour)
		m.mu.Lock()
		auth := m.auths[ids[0]]
		auth.NextRetryAfter = newDeadline
		auth.Quota.NextRecoverAt = newDeadline
		auth.Quota.BackoffLevel = 3
		auth.UpdatedAt = time.Now().Add(time.Second)
		m.mu.Unlock()
		close(release)
		results := <-resultCh
		if len(results) != 1 || !results[0].Success || results[0].Recovered || results[0].State != "stale" {
			t.Fatalf("stale manual success results = %+v", results)
		}
		updated, _ := m.GetByID(ids[0])
		if updated == nil || updated.Quota.BackoffLevel != 3 || !credentialWideQuotaDeadline(updated).Equal(newDeadline) {
			t.Fatalf("stale manual success erased newer failure: %+v", updated)
		}
	})
}

func TestProviderCredentialPolicyRemovalClearsExpiredHistory(t *testing.T) {
	policy := &internalconfig.OpenAICompatibilityCredentialPolicy{
		ScopeStatuses:          []int{http.StatusPaymentRequired},
		InitialCooldownSeconds: 1,
		MaxCooldownSeconds:     30,
		BackoffFactor:          2,
	}
	m, ids := newProviderCredentialPolicyManager(t, 1, policy, &providerCredentialPolicyExecutor{}, 1)
	setProviderCredentialPolicyTestState(m, ids[0], time.Now().Add(-time.Minute), 2)
	cfg := m.runtimeConfigSnapshot().CloneForRuntime()
	cfg.OpenAICompatibility[0].CredentialPolicy = nil
	m.SetConfig(cfg)
	updated, _ := m.GetByID(ids[0])
	if updated == nil || updated.Quota.Exceeded || updated.Quota.BackoffLevel != 0 || updated.Unavailable {
		t.Fatalf("removed policy retained expired history: %+v", updated)
	}
}

func TestProviderCredentialManualTestModelsExcludeImagesAndResolveAlias(t *testing.T) {
	entry := &internalconfig.OpenAICompatibility{Models: []internalconfig.OpenAICompatibilityModel{
		{Name: "image-model", Alias: "image", Image: true},
		{Name: "chat-a", Alias: "alias-a"},
		{Name: "chat-b", Alias: "alias-b"},
	}}
	if got := providerCredentialManualTestModels(entry, "alias-b", 3); len(got) != 1 || got[0] != "chat-b" {
		t.Fatalf("alias model resolution = %v", got)
	}
	if got := providerCredentialManualTestModels(entry, "image", 3); len(got) != 0 {
		t.Fatalf("image model was selected for chat probe: %v", got)
	}
	if got := providerCredentialManualTestModels(entry, "", 1); len(got) != 1 || got[0] != "chat-a" {
		t.Fatalf("default model selection = %v", got)
	}
}

func setProviderCredentialPolicyTestState(m *Manager, authID string, deadline time.Time, backoffLevel int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	auth := m.auths[authID]
	auth.Unavailable = deadline.After(time.Now())
	auth.Status = StatusError
	auth.StatusMessage = "credential policy cooldown"
	auth.NextRetryAfter = deadline
	auth.Quota = QuotaState{Exceeded: true, Reason: providerCredentialPolicyQuotaReason, NextRecoverAt: deadline, BackoffLevel: backoffLevel}
	auth.LastError = &Error{HTTPStatus: http.StatusPaymentRequired, Message: "provider credential policy failure"}
	auth.UpdatedAt = time.Now()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(auth.Clone())
	}
}
