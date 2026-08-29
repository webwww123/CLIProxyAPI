package watcher

import (
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/redisqueue"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type openAICompatCredentialReloadPlan struct {
	providerIndexes []int
	providerNames   []string
	previousEntries int
	currentEntries  int
}

type openAICompatCredentialReloadStats struct {
	added    int
	modified int
	deleted  int
}

func buildOpenAICompatCredentialReloadPlan(oldCfg, newCfg *config.Config) (openAICompatCredentialReloadPlan, bool) {
	var plan openAICompatCredentialReloadPlan
	if oldCfg == nil || newCfg == nil || len(oldCfg.OpenAICompatibility) != len(newCfg.OpenAICompatibility) {
		return plan, false
	}

	oldComparable := *oldCfg
	newComparable := *newCfg
	oldProviders := append([]config.OpenAICompatibility(nil), oldCfg.OpenAICompatibility...)
	newProviders := append([]config.OpenAICompatibility(nil), newCfg.OpenAICompatibility...)
	for index := range oldProviders {
		oldEntries := oldProviders[index].APIKeyEntries
		newEntries := newProviders[index].APIKeyEntries
		if !reflect.DeepEqual(oldEntries, newEntries) {
			plan.providerIndexes = append(plan.providerIndexes, index)
			name := strings.TrimSpace(newProviders[index].Name)
			if name == "" {
				name = "openai-compatibility"
			}
			plan.providerNames = append(plan.providerNames, name)
			plan.previousEntries += len(oldEntries)
			plan.currentEntries += len(newEntries)
		}
		oldProviders[index].APIKeyEntries = nil
		newProviders[index].APIKeyEntries = nil
	}
	if len(plan.providerIndexes) == 0 {
		return openAICompatCredentialReloadPlan{}, false
	}

	oldComparable.OpenAICompatibility = oldProviders
	newComparable.OpenAICompatibility = newProviders
	if !reflect.DeepEqual(&oldComparable, &newComparable) {
		return openAICompatCredentialReloadPlan{}, false
	}
	return plan, true
}

func (w *Watcher) reloadOpenAICompatCredentials(plan openAICompatCredentialReloadPlan) bool {
	if w == nil || len(plan.providerIndexes) == 0 {
		return false
	}

	w.clientsMutex.RLock()
	cfg := w.config
	callback := w.credentialReload
	stateInitialized := w.currentAuths != nil
	queueConfigured := w.authQueue != nil
	w.clientsMutex.RUnlock()
	if cfg == nil || callback == nil || !stateInitialized || !queueConfigured {
		return false
	}
	started := time.Now()
	if !callback(cfg) {
		return false
	}

	auths, errSynthesize := synthesizer.NewConfigSynthesizer().SynthesizeOpenAICompatIndexes(&synthesizer.SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	}, plan.providerIndexes)
	if errSynthesize != nil {
		log.WithError(errSynthesize).Warn("failed to synthesize provider-scoped OpenAI-compatible credentials")
		return false
	}

	updates, stats, okPrepare := w.prepareOpenAICompatCredentialUpdates(auths, plan.providerIndexes)
	if !okPrepare {
		return false
	}
	w.dispatchAuthUpdates(updates)
	redisqueue.NotifyUsageRefresh()

	log.WithFields(log.Fields{
		"providers":                     strings.Join(plan.providerNames, ","),
		"provider_count":                len(plan.providerIndexes),
		"previous_credential_count":     plan.previousEntries,
		"current_credential_count":      plan.currentEntries,
		"credential_add_count":          stats.added,
		"credential_modify_count":       stats.modified,
		"credential_delete_count":       stats.deleted,
		"credential_reload_duration_ms": time.Since(started).Milliseconds(),
	}).Info("provider-scoped credential reload completed")
	return true
}

func (w *Watcher) prepareOpenAICompatCredentialUpdates(auths []*coreauth.Auth, providerIndexes []int) ([]AuthUpdate, openAICompatCredentialReloadStats, bool) {
	var stats openAICompatCredentialReloadStats
	indexSet := make(map[int]struct{}, len(providerIndexes))
	for _, index := range providerIndexes {
		indexSet[index] = struct{}{}
	}

	newState := make(map[string]*coreauth.Auth, len(auths))
	orderedIDs := make([]string, 0, len(auths))
	for _, auth := range auths {
		if auth == nil || auth.ID == "" {
			continue
		}
		if _, exists := newState[auth.ID]; !exists {
			orderedIDs = append(orderedIDs, auth.ID)
		}
		newState[auth.ID] = auth.Clone()
	}

	w.clientsMutex.Lock()
	defer w.clientsMutex.Unlock()
	if w.currentAuths == nil {
		return nil, stats, false
	}

	existingTargets := make(map[string]*coreauth.Auth)
	for id, auth := range w.currentAuths {
		if isOpenAICompatConfigAuthForIndexes(auth, indexSet) {
			existingTargets[id] = auth
		}
	}
	for id := range newState {
		if existing, exists := w.currentAuths[id]; exists && !isOpenAICompatConfigAuthForIndexes(existing, indexSet) {
			return nil, openAICompatCredentialReloadStats{}, false
		}
	}

	updates := make([]AuthUpdate, 0, len(newState)+len(existingTargets))
	for _, id := range orderedIDs {
		auth := newState[id]
		existing, exists := existingTargets[id]
		switch {
		case !exists:
			updates = append(updates, AuthUpdate{Action: AuthUpdateActionAdd, ID: id, Auth: auth.Clone()})
			stats.added++
		case !authEqual(existing, auth):
			updates = append(updates, AuthUpdate{Action: AuthUpdateActionModify, ID: id, Auth: auth.Clone()})
			stats.modified++
		}
		w.currentAuths[id] = auth
	}
	for id := range existingTargets {
		if _, exists := newState[id]; exists {
			continue
		}
		delete(w.currentAuths, id)
		updates = append(updates, AuthUpdate{Action: AuthUpdateActionDelete, ID: id})
		stats.deleted++
	}
	return updates, stats, true
}

func isOpenAICompatConfigAuthForIndexes(auth *coreauth.Auth, indexes map[int]struct{}) bool {
	if auth == nil || auth.AuthSourceKind() != coreauth.AuthSourceConfig || len(auth.Attributes) == 0 {
		return false
	}
	if _, ok := auth.Attributes["compat_name"]; !ok {
		return false
	}
	index, errIndex := strconv.Atoi(strings.TrimSpace(auth.Attributes[coreauth.AttributeConfigIndex]))
	if errIndex != nil {
		return false
	}
	_, ok := indexes[index]
	return ok
}
