package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

const providerCredentialPolicyQuotaReason = "provider_credential_policy"

type providerCredentialPolicyLogEntry struct {
	provider      string
	credentialRef string
	status        int
	cooldown      time.Duration
	backoffLevel  int
}

func isCredentialWideQuotaReason(reason string) bool {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "credential_quota", providerCredentialPolicyQuotaReason:
		return true
	default:
		return false
	}
}

func credentialWideQuotaDeadline(auth *Auth) time.Time {
	if auth == nil {
		return time.Time{}
	}
	deadline := auth.NextRetryAfter
	if auth.Quota.NextRecoverAt.After(deadline) {
		deadline = auth.Quota.NextRecoverAt
	}
	return deadline
}

func credentialWideQuotaActive(auth *Auth, now time.Time) bool {
	return auth != nil && auth.Quota.Exceeded && isCredentialWideQuotaReason(auth.Quota.Reason) && credentialWideQuotaDeadline(auth).After(now)
}

func stableCredentialRef(auth *Auth) string {
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return "unknown"
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(auth.ID)))
	return hex.EncodeToString(sum[:6])
}

func openAICompatConfigForProviderKey(cfg *internalconfig.Config, provider string) *internalconfig.OpenAICompatibility {
	if cfg == nil {
		return nil
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return nil
	}
	for i := range cfg.OpenAICompatibility {
		entry := &cfg.OpenAICompatibility[i]
		if entry.Disabled {
			continue
		}
		if util.OpenAICompatibleProviderKey(entry.Name) == provider {
			return entry
		}
	}
	return nil
}

func (m *Manager) providerCredentialPolicyForAuth(auth *Auth) *internalconfig.OpenAICompatibilityCredentialPolicy {
	if m == nil || auth == nil {
		return nil
	}
	cfg := m.runtimeConfigSnapshot()
	if cfg == nil {
		return nil
	}
	providerKey := ""
	compatName := ""
	if auth.Attributes != nil {
		providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
		compatName = strings.TrimSpace(auth.Attributes["compat_name"])
	}
	entry := resolveOpenAICompatConfigForAuth(cfg, auth, providerKey, compatName)
	if entry == nil {
		return nil
	}
	return entry.CredentialPolicy
}

func providerCredentialPolicyMatchesStatus(policy *internalconfig.OpenAICompatibilityCredentialPolicy, status int) bool {
	if policy == nil || status <= 0 {
		return false
	}
	for _, configured := range policy.ScopeStatuses {
		if configured == status {
			return true
		}
	}
	return false
}

func (m *Manager) isCredentialScopedFailure(auth *Auth, err error) bool {
	if isCredentialScopedError(err) {
		return true
	}
	if m == nil || auth == nil || err == nil {
		return false
	}
	return providerCredentialPolicyMatchesStatus(m.providerCredentialPolicyForAuth(auth), statusCodeFromError(err))
}

func (m *Manager) retrySettingsForProviders(providers []string) (requestRetry int, maxRetryCredentials int, maxWait time.Duration) {
	requestRetry, maxRetryCredentials, maxWait = m.retrySettings()
	if m == nil || len(providers) != 1 {
		return requestRetry, maxRetryCredentials, maxWait
	}
	cfg := m.runtimeConfigSnapshot()
	entry := openAICompatConfigForProviderKey(cfg, providers[0])
	if entry == nil || entry.MaxRetryCredentials == nil || *entry.MaxRetryCredentials < 0 {
		return requestRetry, maxRetryCredentials, maxWait
	}
	return requestRetry, *entry.MaxRetryCredentials, maxWait
}

func providerCredentialPolicyCooldown(policy *internalconfig.OpenAICompatibilityCredentialPolicy, quota QuotaState, now time.Time) (time.Time, int) {
	if policy == nil {
		return time.Time{}, quota.BackoffLevel
	}
	if quota.NextRecoverAt.After(now) {
		return quota.NextRecoverAt, quota.BackoffLevel
	}
	initial := time.Duration(policy.InitialCooldownSeconds) * time.Second
	maximum := time.Duration(policy.MaxCooldownSeconds) * time.Second
	if initial <= 0 {
		initial = time.Minute
	}
	if maximum < initial {
		maximum = initial
	}
	factor := policy.BackoffFactor
	if factor < 2 {
		factor = 2
	}
	level := quota.BackoffLevel
	if level < 0 {
		level = 0
	}
	cooldown := initial
	for i := 0; i < level && cooldown < maximum; i++ {
		if cooldown > maximum/time.Duration(factor) {
			cooldown = maximum
			break
		}
		cooldown *= time.Duration(factor)
	}
	if cooldown > maximum {
		cooldown = maximum
	}
	nextLevel := level
	if cooldown < maximum && nextLevel < 62 {
		nextLevel++
	}
	return now.Add(cooldown), nextLevel
}

func applyProviderCredentialPolicyFailureState(auth *Auth, resultErr *Error, policy *internalconfig.OpenAICompatibilityCredentialPolicy, now time.Time) (time.Duration, int, bool) {
	if auth == nil || policy == nil {
		return 0, 0, false
	}
	if strings.EqualFold(strings.TrimSpace(auth.Quota.Reason), providerCredentialPolicyQuotaReason) && credentialWideQuotaActive(auth, now) {
		return credentialWideQuotaDeadline(auth).Sub(now), auth.Quota.BackoffLevel, false
	}
	quota := auth.Quota
	if !strings.EqualFold(strings.TrimSpace(quota.Reason), providerCredentialPolicyQuotaReason) {
		quota = QuotaState{}
	}
	next, nextLevel := providerCredentialPolicyCooldown(policy, quota, now)
	auth.Unavailable = true
	auth.Status = StatusError
	auth.StatusMessage = "credential policy cooldown"
	auth.NextRetryAfter = next
	auth.Quota = QuotaState{
		Exceeded:      true,
		Reason:        providerCredentialPolicyQuotaReason,
		NextRecoverAt: next,
		BackoffLevel:  nextLevel,
	}
	auth.LastError = providerCredentialPolicyErrorSnapshot(resultErr)
	auth.UpdatedAt = now
	return next.Sub(now), nextLevel, true
}

func providerCredentialPolicyErrorSnapshot(resultErr *Error) *Error {
	if resultErr == nil {
		return nil
	}
	code := strings.TrimSpace(resultErr.Code)
	if code == "" {
		code = providerCredentialPolicyQuotaReason
	}
	return &Error{
		Code:       code,
		Message:    "provider credential policy failure",
		Retryable:  resultErr.Retryable,
		HTTPStatus: resultErr.HTTPStatus,
	}
}

func clearProviderCredentialPolicyState(auth *Auth, now time.Time) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Quota.Reason), providerCredentialPolicyQuotaReason) {
		return false
	}
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
	auth.LastError = nil
	auth.StatusMessage = ""
	auth.Status = StatusActive
	auth.UpdatedAt = now
	updateAggregatedAvailability(auth, now)
	return true
}
