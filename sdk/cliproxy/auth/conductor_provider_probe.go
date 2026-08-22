package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const providerCredentialProbeScanInterval = time.Second

type providerCredentialProbeCandidate struct {
	auth    *Auth
	policy  internalconfig.OpenAICompatibilityCredentialPolicy
	probeAt time.Time
}

func providerCredentialProbeEnabled(policy *internalconfig.OpenAICompatibilityCredentialPolicy) bool {
	return policy != nil && strings.TrimSpace(policy.ProbeModel) != "" && len(policy.ScopeStatuses) > 0
}

func providerCredentialProbeInterval(policy *internalconfig.OpenAICompatibilityCredentialPolicy) time.Duration {
	if !providerCredentialProbeEnabled(policy) {
		return 0
	}
	interval := time.Duration(policy.ProbeIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return interval
}

func providerCredentialProbeLease(policy *internalconfig.OpenAICompatibilityCredentialPolicy) time.Duration {
	lease := 3 * providerCredentialProbeInterval(policy)
	if lease < 30*time.Second {
		lease = 30 * time.Second
	}
	return lease
}

func providerCredentialProbeHeartbeatInterval(policy *internalconfig.OpenAICompatibilityCredentialPolicy) time.Duration {
	interval := providerCredentialProbeLease(policy) / 3
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	return interval
}

func cloneProviderCredentialPolicy(policy *internalconfig.OpenAICompatibilityCredentialPolicy) internalconfig.OpenAICompatibilityCredentialPolicy {
	if policy == nil {
		return internalconfig.OpenAICompatibilityCredentialPolicy{}
	}
	cloned := *policy
	cloned.ScopeStatuses = append([]int(nil), policy.ScopeStatuses...)
	return cloned
}

func providerCredentialPolicyRecoveryDeadline(auth *Auth) time.Time {
	if auth == nil {
		return time.Time{}
	}
	if !auth.Quota.NextRecoverAt.IsZero() {
		return auth.Quota.NextRecoverAt
	}
	return auth.NextRetryAfter
}

func (m *Manager) runProviderCredentialProbeLoop(ctx context.Context) {
	if m == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.scheduleProviderCredentialProbes(ctx, time.Now())
	ticker := time.NewTicker(providerCredentialProbeScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.scheduleProviderCredentialProbes(ctx, now)
		}
	}
}

func (m *Manager) scheduleProviderCredentialProbes(ctx context.Context, now time.Time) {
	if m == nil || (ctx != nil && ctx.Err() != nil) {
		return
	}
	m.mu.RLock()
	auths := make([]*Auth, 0, len(m.auths))
	for _, auth := range m.auths {
		if auth != nil {
			auths = append(auths, auth.Clone())
		}
	}
	m.mu.RUnlock()

	candidates := make([]providerCredentialProbeCandidate, 0)
	for _, auth := range auths {
		policy := m.providerCredentialPolicyForAuth(auth)
		if !providerCredentialProbeEnabled(policy) {
			continue
		}
		if auth.Disabled || auth.Status == StatusDisabled || !auth.Quota.Exceeded || !strings.EqualFold(strings.TrimSpace(auth.Quota.Reason), providerCredentialPolicyQuotaReason) {
			continue
		}
		deadline := providerCredentialPolicyRecoveryDeadline(auth)
		lead := providerCredentialProbeInterval(policy)
		if deadline.IsZero() || deadline.After(now.Add(lead)) {
			continue
		}
		if !m.reserveProviderCredentialProbe(auth.ID, auth.Provider, policy.ProbeConcurrency) {
			continue
		}

		leaseDeadline := now.Add(providerCredentialProbeLease(policy))
		var leased *Auth
		var probeAt time.Time
		m.mu.Lock()
		current := m.auths[auth.ID]
		if current != nil && !current.Disabled && current.Status != StatusDisabled && current.Quota.Exceeded && strings.EqualFold(strings.TrimSpace(current.Quota.Reason), providerCredentialPolicyQuotaReason) {
			currentPolicy := m.providerCredentialPolicyForAuth(current)
			currentDeadline := providerCredentialPolicyRecoveryDeadline(current)
			if providerCredentialProbeEnabled(currentPolicy) && !currentDeadline.IsZero() && !currentDeadline.After(now.Add(providerCredentialProbeInterval(currentPolicy))) {
				current.Unavailable = true
				current.Status = StatusError
				current.NextRetryAfter = leaseDeadline
				current.Quota.Exceeded = true
				current.Quota.Reason = providerCredentialPolicyQuotaReason
				current.Quota.NextRecoverAt = currentDeadline
				current.UpdatedAt = now
				leased = current.Clone()
				policy = currentPolicy
				probeAt = currentDeadline
			}
		}
		m.mu.Unlock()
		if leased == nil {
			m.releaseProviderCredentialProbe(auth.ID, auth.Provider)
			continue
		}
		if m.scheduler != nil {
			m.scheduler.upsertAuth(leased)
		}
		candidates = append(candidates, providerCredentialProbeCandidate{auth: leased, policy: cloneProviderCredentialPolicy(policy), probeAt: probeAt})
	}
	if len(candidates) == 0 {
		return
	}
	m.persistCooldownStates(context.Background())
	for i := range candidates {
		candidate := candidates[i]
		go m.runProviderCredentialProbe(ctx, candidate.auth, candidate.policy, candidate.probeAt)
	}
}

func (m *Manager) reserveProviderCredentialProbe(authID, provider string, concurrency int) bool {
	if m == nil || strings.TrimSpace(authID) == "" {
		return false
	}
	if concurrency <= 0 {
		concurrency = 2
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	m.credentialProbeMu.Lock()
	defer m.credentialProbeMu.Unlock()
	if _, exists := m.credentialProbeInFlight[authID]; exists {
		return false
	}
	if m.credentialProbeProviderInFlight[provider] >= concurrency {
		return false
	}
	m.credentialProbeInFlight[authID] = provider
	m.credentialProbeProviderInFlight[provider]++
	return true
}

func (m *Manager) releaseProviderCredentialProbe(authID, provider string) {
	if m == nil {
		return
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	m.credentialProbeMu.Lock()
	defer m.credentialProbeMu.Unlock()
	reservedProvider, exists := m.credentialProbeInFlight[authID]
	if !exists {
		return
	}
	delete(m.credentialProbeInFlight, authID)
	if provider == "" {
		provider = reservedProvider
	}
	if count := m.credentialProbeProviderInFlight[provider]; count <= 1 {
		delete(m.credentialProbeProviderInFlight, provider)
	} else {
		m.credentialProbeProviderInFlight[provider] = count - 1
	}
}

func (m *Manager) runProviderCredentialProbe(ctx context.Context, auth *Auth, policy internalconfig.OpenAICompatibilityCredentialPolicy, probeAt time.Time) {
	if auth == nil {
		return
	}
	defer m.releaseProviderCredentialProbe(auth.ID, auth.Provider)
	if ctx == nil {
		ctx = context.Background()
	}
	if wait := time.Until(probeAt); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	defer cancelHeartbeat()
	go m.runProviderCredentialProbeLeaseHeartbeat(heartbeatCtx, auth.ID, policy)

	m.mu.RLock()
	current := m.auths[auth.ID]
	var executor ProviderExecutor
	if current != nil {
		auth = current.Clone()
		executor = m.executors[executorKeyFromAuth(current)]
	}
	m.mu.RUnlock()

	var probeErr error
	status := 0
	if auth == nil || executor == nil {
		probeErr = fmt.Errorf("credential probe executor unavailable")
	} else {
		payload, errMarshal := json.Marshal(map[string]any{
			"model": policy.ProbeModel,
			"messages": []map[string]string{{
				"role":    "user",
				"content": "ping",
			}},
			"max_tokens": 1,
			"stream":     false,
		})
		if errMarshal != nil {
			probeErr = errMarshal
		} else {
			response, errExecute := executor.Execute(ctx, auth, cliproxyexecutor.Request{Model: policy.ProbeModel, Payload: payload}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
			probeErr = errExecute
			if probeErr == nil {
				status = http.StatusOK
				probeErr = validateProviderCredentialProbeResponse(response.Payload)
			}
		}
	}
	if probeErr != nil {
		if errorStatus := statusCodeFromError(probeErr); errorStatus != 0 {
			status = errorStatus
		}
	}
	m.finishProviderCredentialProbe(auth.ID, policy, probeErr, status)
}

func (m *Manager) runProviderCredentialProbeLeaseHeartbeat(ctx context.Context, authID string, policy internalconfig.OpenAICompatibilityCredentialPolicy) {
	if m == nil || strings.TrimSpace(authID) == "" {
		return
	}
	interval := providerCredentialProbeHeartbeatInterval(&policy)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if !m.extendProviderCredentialProbeLease(authID, now) {
				return
			}
		}
	}
}

func (m *Manager) extendProviderCredentialProbeLease(authID string, now time.Time) bool {
	if m == nil || strings.TrimSpace(authID) == "" {
		return false
	}
	var snapshot *Auth
	m.mu.Lock()
	auth := m.auths[authID]
	policy := m.providerCredentialPolicyForAuth(auth)
	if auth != nil && !auth.Disabled && auth.Status != StatusDisabled && auth.Quota.Exceeded && strings.EqualFold(strings.TrimSpace(auth.Quota.Reason), providerCredentialPolicyQuotaReason) && providerCredentialProbeEnabled(policy) {
		leaseDeadline := now.Add(providerCredentialProbeLease(policy))
		if leaseDeadline.After(auth.NextRetryAfter) {
			auth.Unavailable = true
			auth.Status = StatusError
			auth.NextRetryAfter = leaseDeadline
			auth.UpdatedAt = now
			snapshot = auth.Clone()
		}
	}
	m.mu.Unlock()
	if snapshot == nil {
		return false
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	m.persistCooldownStates(context.Background())
	return true
}

func validateProviderCredentialProbeResponse(payload []byte) error {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return fmt.Errorf("credential probe returned an empty response")
	}
	if !gjson.ValidBytes(trimmed) {
		return fmt.Errorf("credential probe returned invalid JSON")
	}
	choices := gjson.GetBytes(trimmed, "choices")
	if !choices.Exists() || !choices.IsArray() || len(choices.Array()) == 0 {
		return fmt.Errorf("credential probe returned no choices")
	}
	return nil
}

func (m *Manager) finishProviderCredentialProbe(authID string, policy internalconfig.OpenAICompatibilityCredentialPolicy, probeErr error, status int) {
	if m == nil || strings.TrimSpace(authID) == "" {
		return
	}
	now := time.Now()
	var snapshot *Auth
	var cooldown time.Duration
	var backoffLevel int
	policyDisabled := false
	provider := ""
	credentialRef := "unknown"
	effectivePolicy := policy

	m.mu.Lock()
	auth := m.auths[authID]
	if auth != nil {
		provider = auth.Provider
		credentialRef = stableCredentialRef(auth)
		currentPolicy := m.providerCredentialPolicyForAuth(auth)
		if !providerCredentialProbeEnabled(currentPolicy) {
			policyDisabled = true
			clearProviderCredentialPolicyState(auth, now)
		} else if probeErr == nil {
			clearProviderCredentialPolicyState(auth, now)
		} else {
			effectivePolicy = cloneProviderCredentialPolicy(currentPolicy)
			// The probe lease only fences live traffic while the check is running.
			// Expire that lease before calculating the next real backoff window.
			auth.NextRetryAfter = time.Time{}
			auth.Quota.NextRecoverAt = time.Time{}
			resultErr := resultErrorFromError(probeErr)
			cooldown, backoffLevel, _ = applyProviderCredentialPolicyFailureState(auth, resultErr, &effectivePolicy, now)
		}
		snapshot = auth.Clone()
	}
	m.mu.Unlock()
	if snapshot == nil {
		return
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	m.persistCooldownStates(context.Background())
	fields := log.Fields{
		"provider":       provider,
		"credential_ref": credentialRef,
		"probe_model":    effectivePolicy.ProbeModel,
		"status":         status,
	}
	if policyDisabled {
		log.WithFields(fields).Infof(
			"provider credential probe result discarded after policy change: credential_ref=%s probe_model=%s status=%d",
			credentialRef,
			effectivePolicy.ProbeModel,
			status,
		)
		return
	}
	if probeErr == nil {
		log.WithFields(fields).Infof(
			"provider credential probe recovered credential: credential_ref=%s probe_model=%s status=%d",
			credentialRef,
			effectivePolicy.ProbeModel,
			status,
		)
		return
	}
	cooldownText := cooldown.Round(time.Second).String()
	fields["cooldown"] = cooldownText
	fields["backoff_level"] = backoffLevel
	log.WithFields(fields).Warnf(
		"provider credential probe failed: credential_ref=%s probe_model=%s status=%d cooldown=%s backoff_level=%d",
		credentialRef,
		effectivePolicy.ProbeModel,
		status,
		cooldownText,
		backoffLevel,
	)
}
