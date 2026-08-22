package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type providerCredentialPolicyExecutor struct {
	provider      string
	mu            sync.Mutex
	calls         []string
	failureStatus int
	succeedOnCall int
	probeErr      error
	probeDone     chan struct{}
	probeRelease  <-chan struct{}
	probeOnce     sync.Once
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
	callCount, succeedOnCall, failureStatus := e.recordAttempt(auth)
	if succeedOnCall > 0 && callCount == succeedOnCall {
		return cliproxyexecutor.Response{Payload: []byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)}, nil
	}
	if failureStatus == 0 {
		failureStatus = http.StatusPaymentRequired
	}
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: failureStatus, Message: "credential rejected"}
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
