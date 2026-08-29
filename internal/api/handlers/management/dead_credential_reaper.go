package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	deadCredentialReaperInterval       = time.Second
	deadCredentialRequestDedupWindow   = 10 * time.Minute
	deadCredentialRetryBase            = 2 * time.Second
	deadCredentialRetryMax             = time.Minute
	deadCredentialRateLimitRetryWindow = time.Minute
	deadCredentialStateRetention       = 31 * 24 * time.Hour
	deadCredentialErrorTextLimit       = 8 * 1024
)

type deadCredentialState struct {
	count             int
	firstAt           time.Time
	lastAt            time.Time
	lastStatus        int
	lastRequestID     string
	action            string
	policyFingerprint string
	triggered         bool
}

type deadCredentialCandidate struct {
	providerName        string
	providerKey         string
	authID              string
	credentialRef       string
	apiKey              string
	baseURL             string
	proxyURL            string
	status              int
	policyFingerprint   string
	maxDeletionsPerHour int
	nextAttemptAt       time.Time
	retryCount          int
}

type deadCredentialReaper struct {
	handler *Handler

	removeObserver func()
	closeOnce      sync.Once
	stop           chan struct{}
	done           chan struct{}
	wake           chan struct{}

	mu sync.Mutex
	// operationMu serializes result state transitions with a config mutation.
	// It gives a queued deletion a clear linearization point: a success handled
	// before the deletion lock is acquired cancels the candidate, while a result
	// arriving after the mutation is treated as a fresh observation.
	operationMu   sync.RWMutex
	states        map[string]deadCredentialState
	pending       map[string]deadCredentialCandidate
	deleteHistory map[string][]time.Time
}

func newDeadCredentialReaper(handler *Handler, manager *coreauth.Manager) *deadCredentialReaper {
	if handler == nil || manager == nil {
		return nil
	}
	reaper := &deadCredentialReaper{
		handler:       handler,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		wake:          make(chan struct{}, 1),
		states:        make(map[string]deadCredentialState),
		pending:       make(map[string]deadCredentialCandidate),
		deleteHistory: make(map[string][]time.Time),
	}
	reaper.removeObserver = manager.AddResultObserver(reaper.observeResult)
	go reaper.run()
	return reaper
}

func (r *deadCredentialReaper) close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		if r.removeObserver != nil {
			r.removeObserver()
		}
		close(r.stop)
		<-r.done
	})
}

func (r *deadCredentialReaper) run() {
	ticker := time.NewTicker(deadCredentialReaperInterval)
	defer ticker.Stop()
	defer close(r.done)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.flush()
		case <-r.wake:
			r.flush()
		}
	}
}

func (r *deadCredentialReaper) observeResult(ctx context.Context, result coreauth.Result, auth *coreauth.Auth) {
	if r == nil || result.AuthID == "" {
		return
	}
	if auth == nil {
		if result.Success {
			r.resetState(result.AuthID)
		}
		return
	}
	r.operationMu.RLock()
	defer r.operationMu.RUnlock()
	r.observeResultLocked(ctx, result, auth)
}

func (r *deadCredentialReaper) observeResultLocked(ctx context.Context, result coreauth.Result, auth *coreauth.Auth) {
	if r == nil || auth == nil || result.AuthID == "" {
		return
	}

	if result.Success {
		r.resetStateLocked(result.AuthID)
		return
	}
	if result.Error == nil || !coreauth.IsConfigAPIKeyAuth(auth) {
		if result.Error != nil {
			r.resetStateLocked(result.AuthID)
		}
		return
	}

	providerName, providerKey, policy, ok := r.policyForAuth(auth)
	if !ok || policy == nil || !policy.Enabled || strings.EqualFold(policy.Action, "disabled") {
		r.resetStateLocked(result.AuthID)
		return
	}
	if !deadCredentialErrorMatches(policy, result.Error) {
		// A non-matching credential failure breaks the confirmation sequence. This
		// prevents a 401 separated by an unrelated upstream error from becoming a
		// false dead-key confirmation.
		r.resetStateLocked(result.AuthID)
		return
	}

	now := time.Now()
	policyFingerprint := deadCredentialPolicyFingerprint(policy)
	requestID := logging.GetRequestID(ctx)
	r.mu.Lock()
	state := r.states[result.AuthID]
	if state.policyFingerprint != policyFingerprint {
		state = deadCredentialState{action: policy.Action, policyFingerprint: policyFingerprint}
	}
	if requestID != "" && state.lastRequestID == requestID && now.Sub(state.lastAt) <= deadCredentialRequestDedupWindow {
		// One client request may produce multiple internal attempts (model aliases,
		// refresh, or stream setup). Count it only once toward dead-key confirmation.
		state.lastAt = now
		state.lastStatus = result.Error.HTTPStatus
		r.states[result.AuthID] = state
		r.mu.Unlock()
		return
	}
	window := time.Duration(policy.WindowSeconds) * time.Second
	if state.firstAt.IsZero() || (window > 0 && now.Sub(state.firstAt) > window) {
		state.count = 0
		state.firstAt = now
		state.triggered = false
	}
	state.count++
	state.lastAt = now
	state.lastStatus = result.Error.HTTPStatus
	state.lastRequestID = requestID
	r.states[result.AuthID] = state
	count := state.count
	trigger := count >= policy.Confirmations && !state.triggered
	if trigger {
		state.triggered = true
		r.states[result.AuthID] = state
	}
	r.mu.Unlock()

	fields := log.Fields{
		"provider":       providerName,
		"provider_key":   providerKey,
		"credential_ref": deadCredentialRef(auth.ID),
		"status":         result.Error.HTTPStatus,
		"confirmations":  count,
		"required":       policy.Confirmations,
		"action":         policy.Action,
	}
	if !trigger {
		// Keep the diagnostic useful without turning a hot dead key into a log
		// amplifier: report the first observation and the one immediately before
		// the configured confirmation threshold.
		if count == 1 || count+1 == policy.Confirmations {
			log.WithFields(fields).Info("dead credential failure recorded")
		}
		return
	}

	if !strings.EqualFold(policy.Action, "delete") {
		log.WithFields(fields).Warn("dead credential matched in dry-run mode; no credential removed")
		return
	}

	apiKey := ""
	baseURL := ""
	proxyURL := strings.TrimSpace(auth.ProxyURL)
	if auth.Attributes != nil {
		apiKey = strings.TrimSpace(auth.Attributes["api_key"])
		baseURL = strings.TrimSpace(auth.Attributes["base_url"])
	}
	if apiKey == "" {
		log.WithFields(fields).Warn("dead credential matched but has no config API key identity; removal skipped")
		return
	}

	candidate := deadCredentialCandidate{
		providerName:        providerName,
		providerKey:         providerKey,
		authID:              auth.ID,
		credentialRef:       deadCredentialRef(auth.ID),
		apiKey:              apiKey,
		baseURL:             baseURL,
		proxyURL:            proxyURL,
		status:              result.Error.HTTPStatus,
		policyFingerprint:   policyFingerprint,
		maxDeletionsPerHour: policy.MaxDeletionsPerHour,
	}
	key := deadCredentialPendingKey(candidate)
	r.mu.Lock()
	r.pending[key] = candidate
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
	log.WithFields(fields).Warn("dead credential queued for removal")
}

func (r *deadCredentialReaper) resetState(authID string) {
	if r == nil || strings.TrimSpace(authID) == "" {
		return
	}
	r.operationMu.RLock()
	defer r.operationMu.RUnlock()
	r.resetStateLocked(authID)
}

func (r *deadCredentialReaper) resetStateLocked(authID string) {
	if r == nil || strings.TrimSpace(authID) == "" {
		return
	}
	r.mu.Lock()
	delete(r.states, authID)
	for key, candidate := range r.pending {
		if candidate.authID == authID {
			delete(r.pending, key)
		}
	}
	r.mu.Unlock()
}

func deadCredentialPolicyFingerprint(policy *config.OpenAICompatibilityDeadCredentialPolicy) string {
	if policy == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%t|%d|%d|%s|%d|", policy.Enabled, policy.Confirmations, policy.WindowSeconds, strings.ToLower(strings.TrimSpace(policy.Action)), policy.MaxDeletionsPerHour)
	for _, status := range policy.Statuses {
		fmt.Fprintf(&b, "s%d,", status)
	}
	b.WriteByte('|')
	for _, pattern := range policy.Match {
		b.WriteString(strings.ToLower(strings.TrimSpace(pattern)))
		b.WriteByte(',')
	}
	b.WriteByte('|')
	for _, pattern := range policy.MatchRegexr {
		b.WriteString(strings.TrimSpace(pattern))
		b.WriteByte(',')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

func (r *deadCredentialReaper) policyForAuth(auth *coreauth.Auth) (string, string, *config.OpenAICompatibilityDeadCredentialPolicy, bool) {
	if r == nil || r.handler == nil || auth == nil || auth.Attributes == nil {
		return "", "", nil, false
	}
	providerKey := strings.ToLower(strings.TrimSpace(auth.Attributes["provider_key"]))
	compatName := strings.TrimSpace(auth.Attributes["compat_name"])
	configIndex, errConfigIndex := strconv.Atoi(strings.TrimSpace(auth.Attributes["config_index"]))
	if providerKey == "" && compatName == "" {
		return "", "", nil, false
	}

	r.handler.mu.Lock()
	defer r.handler.mu.Unlock()
	if r.handler.cfg == nil {
		return "", "", nil, false
	}
	matches := make([]int, 0, 1)
	for i := range r.handler.cfg.OpenAICompatibility {
		entry := &r.handler.cfg.OpenAICompatibility[i]
		if entry.Disabled {
			continue
		}
		entryKey := util.OpenAICompatibleProviderKey(entry.Name)
		if providerKey != "" && entryKey != providerKey && !strings.EqualFold(entry.Name, compatName) {
			continue
		}
		if providerKey == "" && !strings.EqualFold(entry.Name, compatName) {
			continue
		}
		matches = append(matches, i)
	}
	if errConfigIndex == nil && configIndex >= 0 && configIndex < len(r.handler.cfg.OpenAICompatibility) {
		if len(matches) == 0 {
			return "", "", nil, false
		}
		found := false
		for _, index := range matches {
			if index == configIndex {
				matches = []int{index}
				found = true
				break
			}
		}
		if !found {
			return "", "", nil, false
		}
	}
	if len(matches) != 1 {
		return "", "", nil, false
	}
	entry := &r.handler.cfg.OpenAICompatibility[matches[0]]
	entryKey := util.OpenAICompatibleProviderKey(entry.Name)
	normalizedPolicy := config.NormalizeOpenAICompatibilityCredentialPolicy(entry.CredentialPolicy)
	if normalizedPolicy == nil || normalizedPolicy.DeadCredential == nil {
		return entry.Name, entryKey, nil, false
	}
	dead := *normalizedPolicy.DeadCredential
	dead.Statuses = append([]int(nil), normalizedPolicy.DeadCredential.Statuses...)
	dead.Match = append([]string(nil), normalizedPolicy.DeadCredential.Match...)
	dead.MatchRegexr = append([]string(nil), normalizedPolicy.DeadCredential.MatchRegexr...)
	return entry.Name, entryKey, &dead, true
}

func deadCredentialErrorMatches(policy *config.OpenAICompatibilityDeadCredentialPolicy, err *coreauth.Error) bool {
	if policy == nil || err == nil || err.HTTPStatus < 400 || err.HTTPStatus > 599 {
		return false
	}
	if err.Code == coreauth.ErrorCodeRequestScoped || err.Code == coreauth.ErrorCodeConnectionLifecycle || err.Code == coreauth.ErrorCodeForceCooldown {
		return false
	}
	statuses := policy.Statuses
	if len(statuses) == 0 {
		statuses = []int{401}
	}
	statusMatch := false
	for _, status := range statuses {
		if status == err.HTTPStatus {
			statusMatch = true
			break
		}
	}
	if !statusMatch {
		return false
	}
	if len(policy.Match) == 0 && len(policy.MatchRegexr) == 0 {
		return true
	}
	body := strings.TrimSpace(err.Code + " " + err.Message)
	if len(body) > deadCredentialErrorTextLimit {
		body = body[:deadCredentialErrorTextLimit]
	}
	lowerBody := strings.ToLower(body)
	for _, pattern := range policy.Match {
		if pattern != "" && strings.Contains(lowerBody, strings.ToLower(pattern)) {
			return true
		}
	}
	for _, pattern := range policy.MatchRegexr {
		if pattern == "" {
			continue
		}
		compiled, errCompile := regexp.Compile(pattern)
		if errCompile == nil && compiled.MatchString(body) {
			return true
		}
	}
	return false
}

func (r *deadCredentialReaper) flush() {
	if r == nil || r.handler == nil {
		return
	}
	r.operationMu.Lock()
	defer r.operationMu.Unlock()
	r.flushLocked()
}

func (r *deadCredentialReaper) flushLocked() {
	if r == nil || r.handler == nil {
		return
	}
	now := time.Now()
	r.mu.Lock()
	r.pruneExpiredStateLocked(now)
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return
	}
	pending := make([]deadCredentialCandidate, 0, len(r.pending))
	for key, candidate := range r.pending {
		if !candidate.nextAttemptAt.IsZero() && now.Before(candidate.nextAttemptAt) {
			continue
		}
		delete(r.pending, key)
		if r.candidateStillTriggeredLocked(candidate) {
			pending = append(pending, candidate)
		}
	}
	r.mu.Unlock()

	sort.Slice(pending, func(i, j int) bool {
		if pending[i].providerKey != pending[j].providerKey {
			return pending[i].providerKey < pending[j].providerKey
		}
		if pending[i].baseURL != pending[j].baseURL {
			return pending[i].baseURL < pending[j].baseURL
		}
		return pending[i].authID < pending[j].authID
	})
	groups := make(map[string][]deadCredentialCandidate)
	for _, candidate := range pending {
		groupKey := deadCredentialGroupKey(candidate)
		groups[groupKey] = append(groups[groupKey], candidate)
	}
	groupKeys := make([]string, 0, len(groups))
	for groupKey := range groups {
		groupKeys = append(groupKeys, groupKey)
	}
	sort.Strings(groupKeys)

	for _, groupKey := range groupKeys {
		group := groups[groupKey]
		group = r.filterCandidatesStillTriggered(group)
		if len(group) == 0 {
			continue
		}
		provider := group[0].providerKey
		limit := group[0].maxDeletionsPerHour
		if limit <= 0 {
			limit = 10
		}
		for _, candidate := range group[1:] {
			if candidate.maxDeletionsPerHour > 0 && candidate.maxDeletionsPerHour < limit {
				limit = candidate.maxDeletionsPerHour
			}
		}
		now := time.Now()
		r.mu.Lock()
		history := r.deleteHistory[provider]
		keptHistory := history[:0]
		for _, at := range history {
			if now.Sub(at) < time.Hour {
				keptHistory = append(keptHistory, at)
			}
		}
		r.deleteHistory[provider] = keptHistory
		available := limit - len(keptHistory)
		r.mu.Unlock()
		if available <= 0 {
			retryAt := now.Add(deadCredentialRateLimitRetryWindow)
			for _, at := range keptHistory {
				if expiry := at.Add(time.Hour); expiry.After(now) && expiry.Before(retryAt) {
					retryAt = expiry
				}
			}
			r.requeueUntil(group, retryAt)
			log.WithFields(log.Fields{"provider": provider, "base_url_ref": deadCredentialBaseURLRef(group[0].baseURL), "pending": len(group), "limit_per_hour": limit}).Warn("dead credential delete rate limit reached")
			continue
		}
		if available > len(group) {
			available = len(group)
		}
		selected := group[:available]
		if len(group) > available {
			r.requeueAfter(group[available:], time.Second)
		}
		removed, backupDir, errRemove := r.handler.removeDeadCredentialBatch(context.Background(), provider, selected)
		if errRemove != nil {
			r.requeue(selected)
			log.WithFields(log.Fields{"provider": provider, "candidate_count": len(selected)}).WithError(errRemove).Error("dead credential batch removal failed")
			continue
		}
		if removed > 0 {
			r.mu.Lock()
			for i := 0; i < removed; i++ {
				r.deleteHistory[provider] = append(r.deleteHistory[provider], time.Now())
			}
			r.mu.Unlock()
		}
		// A successful config write is the end of this confirmation attempt,
		// including candidates that became stale or ambiguous before the write.
		// Let a future fresh sequence re-evaluate them instead of retaining stale
		// state indefinitely.
		for _, candidate := range selected {
			r.resetStateLocked(candidate.authID)
		}
		log.WithFields(log.Fields{"provider": provider, "base_url_ref": deadCredentialBaseURLRef(selected[0].baseURL), "candidate_count": len(selected), "removed_count": removed, "backup_dir": backupDir}).Warn("dead credential batch removal completed")
	}
}

func (r *deadCredentialReaper) pruneExpiredStateLocked(now time.Time) {
	if r == nil {
		return
	}
	for authID, state := range r.states {
		if state.lastAt.IsZero() || now.Sub(state.lastAt) <= deadCredentialStateRetention {
			continue
		}
		delete(r.states, authID)
		for key, candidate := range r.pending {
			if candidate.authID == authID {
				delete(r.pending, key)
			}
		}
	}
	for key, candidate := range r.pending {
		state, ok := r.states[candidate.authID]
		if !ok || (!state.lastAt.IsZero() && now.Sub(state.lastAt) > deadCredentialStateRetention) {
			delete(r.pending, key)
		}
	}
}

func (r *deadCredentialReaper) filterCandidatesStillTriggered(candidates []deadCredentialCandidate) []deadCredentialCandidate {
	if r == nil || len(candidates) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	filtered := candidates[:0]
	for _, candidate := range candidates {
		if r.candidateStillTriggeredLocked(candidate) {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func (r *deadCredentialReaper) candidateStillTriggeredLocked(candidate deadCredentialCandidate) bool {
	state, ok := r.states[candidate.authID]
	return ok && state.triggered && state.policyFingerprint == candidate.policyFingerprint
}

func (r *deadCredentialReaper) requeue(candidates []deadCredentialCandidate) {
	if r == nil || len(candidates) == 0 {
		return
	}
	r.requeueAfter(candidates, 0)
}

func (r *deadCredentialReaper) requeueAfter(candidates []deadCredentialCandidate, delay time.Duration) {
	if r == nil || len(candidates) == 0 {
		return
	}
	now := time.Now()
	r.mu.Lock()
	for _, candidate := range candidates {
		candidateDelay := delay
		if candidateDelay <= 0 {
			candidate.retryCount++
			candidateDelay = deadCredentialRetryBase
			for i := 1; i < candidate.retryCount && candidateDelay < deadCredentialRetryMax; i++ {
				candidateDelay *= 2
			}
			if candidateDelay > deadCredentialRetryMax {
				candidateDelay = deadCredentialRetryMax
			}
		}
		candidate.nextAttemptAt = now.Add(candidateDelay)
		key := deadCredentialPendingKey(candidate)
		r.pending[key] = candidate
	}
	r.mu.Unlock()
}

func (r *deadCredentialReaper) requeueUntil(candidates []deadCredentialCandidate, at time.Time) {
	if r == nil || len(candidates) == 0 {
		return
	}
	if at.IsZero() {
		at = time.Now().Add(deadCredentialRateLimitRetryWindow)
	}
	r.mu.Lock()
	for _, candidate := range candidates {
		candidate.nextAttemptAt = at
		key := deadCredentialPendingKey(candidate)
		r.pending[key] = candidate
	}
	r.mu.Unlock()
}

func deadCredentialGroupKey(candidate deadCredentialCandidate) string {
	return strings.ToLower(strings.TrimSpace(candidate.providerKey)) + "\x00" + strings.ToLower(normalizeDeadCredentialBaseURL(candidate.baseURL))
}

func deadCredentialPendingKey(candidate deadCredentialCandidate) string {
	return deadCredentialGroupKey(candidate) + "\x00" + strings.TrimSpace(candidate.authID)
}

func normalizeDeadCredentialBaseURL(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

func deadCredentialBaseURLRef(baseURL string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return "<empty>"
	}
	sum := sha256.Sum256([]byte(baseURL))
	return hex.EncodeToString(sum[:6])
}

func deadCredentialRef(authID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(authID)))
	return hex.EncodeToString(sum[:6])
}

func (h *Handler) removeDeadCredentialBatch(ctx context.Context, providerKey string, candidates []deadCredentialCandidate) (int, string, error) {
	if h == nil || len(candidates) == 0 {
		return 0, "", nil
	}
	if strings.TrimSpace(h.configFilePath) == "" {
		return 0, "", fmt.Errorf("config file path is empty")
	}

	h.mu.Lock()
	if h.cfg == nil {
		h.mu.Unlock()
		return 0, "", fmt.Errorf("configuration is unavailable")
	}
	providerIndexes := make([]int, 0, 1)
	for i := range h.cfg.OpenAICompatibility {
		if h.cfg.OpenAICompatibility[i].Disabled {
			continue
		}
		if util.OpenAICompatibleProviderKey(h.cfg.OpenAICompatibility[i].Name) == strings.ToLower(strings.TrimSpace(providerKey)) {
			providerIndexes = append(providerIndexes, i)
		}
	}
	if len(providerIndexes) == 0 {
		log.WithFields(log.Fields{"provider": providerKey, "candidate_count": len(candidates)}).Info("dead credential removal skipped because provider is no longer configured")
		h.mu.Unlock()
		return 0, "", nil
	}
	providerIndex := providerIndexes[0]
	if len(candidates) > 0 {
		baseURL := normalizeDeadCredentialBaseURL(candidates[0].baseURL)
		if baseURL != "" {
			filtered := providerIndexes[:0]
			for _, index := range providerIndexes {
				if strings.EqualFold(normalizeDeadCredentialBaseURL(h.cfg.OpenAICompatibility[index].BaseURL), baseURL) {
					filtered = append(filtered, index)
				}
			}
			providerIndexes = filtered
		}
	}
	if len(providerIndexes) != 1 {
		log.WithFields(log.Fields{"provider": providerKey, "candidate_count": len(candidates)}).Warn("dead credential removal skipped because provider identity is ambiguous")
		h.mu.Unlock()
		return 0, "", nil
	}
	providerIndex = providerIndexes[0]

	entry := h.cfg.OpenAICompatibility[providerIndex]
	normalizedPolicy := config.NormalizeOpenAICompatibilityCredentialPolicy(entry.CredentialPolicy)
	if normalizedPolicy == nil || normalizedPolicy.DeadCredential == nil || !normalizedPolicy.DeadCredential.Enabled || !strings.EqualFold(normalizedPolicy.DeadCredential.Action, "delete") {
		log.WithFields(log.Fields{"provider": entry.Name, "base_url_ref": deadCredentialBaseURLRef(entry.BaseURL), "candidate_count": len(candidates)}).Info("dead credential removal skipped because policy is no longer enabled")
		h.mu.Unlock()
		return 0, "", nil
	}
	currentFingerprint := deadCredentialPolicyFingerprint(normalizedPolicy.DeadCredential)
	validCandidates := candidates[:0]
	for _, candidate := range candidates {
		if candidate.policyFingerprint != currentFingerprint {
			log.WithFields(log.Fields{"provider": entry.Name, "credential_ref": candidate.credentialRef}).Info("dead credential removal skipped because policy changed")
			continue
		}
		validCandidates = append(validCandidates, candidate)
	}
	candidates = validCandidates
	if len(candidates) == 0 {
		h.mu.Unlock()
		return 0, "", nil
	}
	removeIndexes := make(map[int]struct{}, len(candidates))
	for _, candidate := range candidates {
		matches := make([]int, 0, 1)
		for index, configured := range entry.APIKeyEntries {
			if strings.TrimSpace(configured.APIKey) != candidate.apiKey {
				continue
			}
			if strings.TrimSpace(configured.ProxyURL) != candidate.proxyURL {
				continue
			}
			if candidate.baseURL != "" && !strings.EqualFold(normalizeDeadCredentialBaseURL(entry.BaseURL), normalizeDeadCredentialBaseURL(candidate.baseURL)) {
				continue
			}
			matches = append(matches, index)
		}
		if len(matches) != 1 {
			log.WithFields(log.Fields{"provider": entry.Name, "credential_ref": candidate.credentialRef, "match_count": len(matches)}).Warn("dead credential removal skipped because config identity is not unique")
			continue
		}
		removeIndexes[matches[0]] = struct{}{}
	}
	if len(removeIndexes) == 0 {
		h.mu.Unlock()
		return 0, "", nil
	}

	before, errRead := os.ReadFile(h.configFilePath)
	if errRead != nil {
		h.mu.Unlock()
		return 0, "", fmt.Errorf("read config backup source: %w", errRead)
	}
	backupDir := filepath.Join(filepath.Dir(h.configFilePath), "credential-cleanup", fmt.Sprintf("%s-%s", safeCredentialPathPart(entry.Name), time.Now().UTC().Format("20060102T150405.000000000Z")))
	if errMkdir := os.MkdirAll(backupDir, 0o700); errMkdir != nil {
		h.mu.Unlock()
		return 0, "", fmt.Errorf("create credential backup directory: %w", errMkdir)
	}
	if errWrite := writePrivateFile(filepath.Join(backupDir, "config-before.yaml"), before, 0o600); errWrite != nil {
		h.mu.Unlock()
		return 0, "", fmt.Errorf("write credential config backup: %w", errWrite)
	}
	summary := make(map[string]any)
	summary["provider"] = entry.Name
	summary["captured_at_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	summary["before_count"] = len(entry.APIKeyEntries)
	summary["removed_count"] = len(removeIndexes)
	refs := make([]string, 0, len(removeIndexes))
	for _, candidate := range candidates {
		if index, ok := removeIndexesForCandidate(entry.APIKeyEntries, entry.BaseURL, candidate); ok {
			if _, removed := removeIndexes[index]; !removed {
				continue
			}
			refs = append(refs, candidate.credentialRef)
		}
	}
	sort.Strings(refs)
	summary["credential_refs"] = refs
	if errWrite := writePrivateJSON(filepath.Join(backupDir, "removal-summary.json"), summary); errWrite != nil {
		h.mu.Unlock()
		return 0, "", fmt.Errorf("write credential removal summary: %w", errWrite)
	}

	oldEntries := entry.APIKeyEntries
	updatedEntries := make([]config.OpenAICompatibilityAPIKey, 0, len(oldEntries)-len(removeIndexes))
	for index, configured := range oldEntries {
		if _, remove := removeIndexes[index]; remove {
			continue
		}
		updatedEntries = append(updatedEntries, configured)
	}
	entry.APIKeyEntries = updatedEntries
	h.cfg.OpenAICompatibility[providerIndex] = entry
	if errSave := config.SaveConfigPreserveComments(h.configFilePath, h.cfg); errSave != nil {
		h.cfg.OpenAICompatibility[providerIndex].APIKeyEntries = oldEntries
		h.mu.Unlock()
		return 0, "", fmt.Errorf("save config after dead credential removal: %w", errSave)
	}
	snapshot := h.reloadSnapshotConfigLocked()
	h.mu.Unlock()

	if snapshot.cfg != nil {
		h.reloadConfigAfterManagementSaveAsync(ctx, snapshot)
	}
	return len(removeIndexes), backupDir, nil
}

func removeIndexesForCandidate(entries []config.OpenAICompatibilityAPIKey, providerBaseURL string, candidate deadCredentialCandidate) (int, bool) {
	match := -1
	if candidate.baseURL != "" && !strings.EqualFold(normalizeDeadCredentialBaseURL(providerBaseURL), normalizeDeadCredentialBaseURL(candidate.baseURL)) {
		return -1, false
	}
	for index, configured := range entries {
		if strings.TrimSpace(configured.APIKey) == candidate.apiKey && strings.TrimSpace(configured.ProxyURL) == candidate.proxyURL {
			if match >= 0 {
				return -1, false
			}
			match = index
		}
	}
	return match, match >= 0
}

func safeCredentialPathPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "provider"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "provider"
	}
	return b.String()
}

func writePrivateFile(path string, data []byte, mode os.FileMode) error {
	file, errOpen := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if errOpen != nil {
		return errOpen
	}
	if _, errWrite := file.Write(data); errWrite != nil {
		_ = file.Close()
		return errWrite
	}
	if errSync := file.Sync(); errSync != nil {
		_ = file.Close()
		return errSync
	}
	if errClose := file.Close(); errClose != nil {
		return errClose
	}
	return os.Chmod(path, mode)
}

func writePrivateJSON(path string, value any) error {
	data, errMarshal := json.MarshalIndent(value, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	data = append(data, '\n')
	return writePrivateFile(path, data, 0o600)
}
