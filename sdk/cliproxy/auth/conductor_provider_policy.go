package auth

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"strconv"
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
	rule          string
	cooldown      time.Duration
	backoffLevel  int
}

type providerCredentialPenalty struct {
	rule                   string
	initialCooldownSeconds int
	maxCooldownSeconds     int
	backoffFactor          int
	jitterPercent          int
}

// ProviderCredentialPolicyStatus is a secret-safe snapshot of retained
// provider credential policy state for management surfaces.
type ProviderCredentialPolicyStatus struct {
	AuthID         string    `json:"-"`
	Provider       string    `json:"provider"`
	CredentialRef  string    `json:"credential_ref"`
	State          string    `json:"state"`
	BackoffLevel   int       `json:"backoff_level"`
	LastHTTPStatus int       `json:"last_http_status,omitempty"`
	NextRetryAfter time.Time `json:"next_retry_after,omitempty"`
	StateUpdatedAt time.Time `json:"state_updated_at,omitempty"`
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
	if hasProviderCredentialPolicyState(auth) {
		deadline := auth.Quota.NextRecoverAt
		statusMessage := strings.ToLower(strings.TrimSpace(auth.StatusMessage))
		policyFence := statusMessage == "credential policy cooldown" || statusMessage == providerCredentialPolicyQuotaReason
		if policyFence && auth.NextRetryAfter.After(deadline) {
			deadline = auth.NextRetryAfter
		}
		return deadline
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

func hasProviderCredentialPolicyState(auth *Auth) bool {
	return auth != nil && strings.EqualFold(strings.TrimSpace(auth.Quota.Reason), providerCredentialPolicyQuotaReason)
}

// ProviderCredentialPolicyStatusForAuth returns the derived policy state for
// one auth without exposing its raw credential ID as the public reference.
func ProviderCredentialPolicyStatusForAuth(auth *Auth, now time.Time) (ProviderCredentialPolicyStatus, bool) {
	if !hasProviderCredentialPolicyState(auth) {
		return ProviderCredentialPolicyStatus{}, false
	}
	state := "eligible"
	if credentialWideQuotaActive(auth, now) {
		state = "cooling"
	} else if !auth.Quota.Exceeded {
		state = "healthy"
	}
	status := ProviderCredentialPolicyStatus{
		AuthID:         auth.ID,
		Provider:       strings.TrimSpace(auth.Provider),
		CredentialRef:  stableCredentialRef(auth),
		State:          state,
		BackoffLevel:   auth.Quota.BackoffLevel,
		NextRetryAfter: credentialWideQuotaDeadline(auth),
		StateUpdatedAt: auth.UpdatedAt,
	}
	if auth.LastError != nil {
		status.LastHTTPStatus = auth.LastError.HTTPStatus
	}
	return status, true
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
	return providerCredentialPolicyForAuthConfig(m.runtimeConfigSnapshot(), auth)
}

func providerCredentialPolicyForAuthConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.OpenAICompatibilityCredentialPolicy {
	if auth == nil {
		return nil
	}
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
	for _, rule := range policy.PenaltyRules {
		if rule.Status == status {
			return true
		}
	}
	return false
}

func providerCredentialPolicyHasMatchers(policy *internalconfig.OpenAICompatibilityCredentialPolicy) bool {
	return policy != nil && (len(policy.ScopeStatuses) > 0 || len(policy.PenaltyRules) > 0)
}

func baseProviderCredentialPenalty(policy *internalconfig.OpenAICompatibilityCredentialPolicy) providerCredentialPenalty {
	if policy == nil {
		return providerCredentialPenalty{}
	}
	return providerCredentialPenalty{
		initialCooldownSeconds: policy.InitialCooldownSeconds,
		maxCooldownSeconds:     policy.MaxCooldownSeconds,
		backoffFactor:          policy.BackoffFactor,
		jitterPercent:          policy.CooldownJitterPercent,
	}
}

func providerCredentialPolicyMatch(policy *internalconfig.OpenAICompatibilityCredentialPolicy, err error) (providerCredentialPenalty, bool) {
	if policy == nil || err == nil {
		return providerCredentialPenalty{}, false
	}
	status := statusCodeFromError(err)
	if status <= 0 {
		return providerCredentialPenalty{}, false
	}
	body := extractErrorBody(err)
	lowerBody := strings.ToLower(body)
	for _, rule := range policy.PenaltyRules {
		if rule.Status != status {
			continue
		}
		matched := len(rule.Match) == 0 && len(rule.MatchRegexr) == 0
		for _, pattern := range rule.Match {
			if pattern != "" && strings.Contains(lowerBody, strings.ToLower(pattern)) {
				matched = true
				break
			}
		}
		if !matched {
			for _, pattern := range rule.MatchRegexr {
				if pattern == "" {
					continue
				}
				re, errCompile := regexp.Compile(pattern)
				if errCompile == nil && re.MatchString(body) {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}
		return providerCredentialPenalty{
			rule:                   strings.TrimSpace(rule.Name),
			initialCooldownSeconds: rule.InitialCooldownSeconds,
			maxCooldownSeconds:     rule.MaxCooldownSeconds,
			backoffFactor:          rule.BackoffFactor,
			jitterPercent:          policy.CooldownJitterPercent,
		}, true
	}
	if providerCredentialPolicyMatchesStatus(&internalconfig.OpenAICompatibilityCredentialPolicy{ScopeStatuses: policy.ScopeStatuses}, status) {
		return baseProviderCredentialPenalty(policy), true
	}
	return providerCredentialPenalty{}, false
}

func (m *Manager) isCredentialScopedFailure(auth *Auth, err error) bool {
	if isCredentialScopedError(err) {
		return true
	}
	if m == nil || auth == nil || err == nil {
		return false
	}
	_, matched := providerCredentialPolicyMatch(m.providerCredentialPolicyForAuth(auth), err)
	return matched
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
	return providerCredentialPenaltyCooldown(baseProviderCredentialPenalty(policy), quota, now, "")
}

func providerCredentialPenaltyCooldown(penalty providerCredentialPenalty, quota QuotaState, now time.Time, seed string) (time.Time, int) {
	if penalty.initialCooldownSeconds <= 0 && penalty.maxCooldownSeconds <= 0 {
		return time.Time{}, quota.BackoffLevel
	}
	if quota.NextRecoverAt.After(now) {
		return quota.NextRecoverAt, quota.BackoffLevel
	}
	initial := time.Duration(penalty.initialCooldownSeconds) * time.Second
	maximum := time.Duration(penalty.maxCooldownSeconds) * time.Second
	if initial <= 0 {
		initial = time.Minute
	}
	if maximum < initial {
		maximum = initial
	}
	factor := penalty.backoffFactor
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
	atMaximum := cooldown >= maximum
	cooldown = jitterProviderCredentialCooldown(cooldown, maximum, penalty.jitterPercent, seed, level, penalty.rule)
	nextLevel := level
	if !atMaximum && nextLevel < 62 {
		nextLevel++
	}
	return now.Add(cooldown), nextLevel
}

func jitterProviderCredentialCooldown(cooldown, maximum time.Duration, percent int, seed string, level int, rule string) time.Duration {
	if cooldown <= 0 || percent <= 0 {
		return cooldown
	}
	if percent > 50 {
		percent = 50
	}
	sum := sha256.Sum256([]byte(seed + "|" + rule + "|" + strconv.Itoa(level)))
	span := uint64(percent*200 + 1)
	offsetBasisPoints := int64(binary.BigEndian.Uint64(sum[:8])%span) - int64(percent*100)
	jittered := cooldown + time.Duration(int64(cooldown)*offsetBasisPoints/10_000)
	if jittered < time.Second {
		jittered = time.Second
	}
	if maximum > 0 && jittered > maximum {
		jittered = maximum
	}
	return jittered
}

func applyProviderCredentialPolicyFailureState(auth *Auth, resultErr *Error, policy *internalconfig.OpenAICompatibilityCredentialPolicy, penalty providerCredentialPenalty, now time.Time) (time.Duration, int, bool) {
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
	if penalty.initialCooldownSeconds <= 0 {
		penalty = baseProviderCredentialPenalty(policy)
	}
	next, nextLevel := providerCredentialPenaltyCooldown(penalty, quota, now, auth.ID)
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
	if !hasProviderCredentialPolicyState(auth) {
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
	if hasModelError(auth, now) {
		auth.Status = StatusError
	}
	return true
}

func recoverProviderCredentialPolicyState(auth *Auth, now time.Time) bool {
	if !hasProviderCredentialPolicyState(auth) {
		return false
	}
	backoffLevel := auth.Quota.BackoffLevel
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
	if backoffLevel > 0 {
		auth.Quota = QuotaState{
			Reason:       providerCredentialPolicyQuotaReason,
			BackoffLevel: backoffLevel,
		}
	}
	auth.LastError = nil
	auth.StatusMessage = ""
	auth.Status = StatusActive
	auth.UpdatedAt = now
	updateAggregatedAvailability(auth, now)
	if hasModelError(auth, now) {
		auth.Status = StatusError
	}
	return true
}
