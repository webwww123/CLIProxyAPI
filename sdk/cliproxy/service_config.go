package cliproxy

import (
	"context"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
)

func (s *Service) applyConfigUpdate(newCfg *config.Config) {
	s.applyConfigUpdateWithAuthSynthesis(context.Background(), newCfg, true)
}

func (s *Service) applyWatcherConfigUpdate(newCfg *config.Config) {
	s.applyConfigUpdateWithAuthSynthesis(context.Background(), newCfg, false)
}

func (s *Service) applyWatcherCredentialConfigUpdate(newCfg *config.Config) bool {
	commit := s.commitConfigUpdate(newCfg)
	if commit.cfg == nil {
		return false
	}
	return s.applyCredentialConfigRuntime(context.Background(), commit)
}

type configCommit struct {
	cfg      *config.Config
	sequence uint64
}

type routingRuntimeState struct {
	strategy           string
	sessionAffinity    bool
	sessionAffinityTTL time.Duration
}

func normalizedRoutingRuntimeState(cfg *config.Config) routingRuntimeState {
	state := routingRuntimeState{
		strategy:           "round-robin",
		sessionAffinityTTL: time.Hour,
	}
	if cfg == nil {
		return state
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Routing.Strategy)) {
	case "weighted-round-robin", "weightedroundrobin", "wrr":
		state.strategy = "weighted-round-robin"
	case "fill-first", "fillfirst", "ff":
		state.strategy = "fill-first"
	}
	state.sessionAffinity = cfg.Routing.SessionAffinity
	if ttl := strings.TrimSpace(cfg.Routing.SessionAffinityTTL); ttl != "" {
		if parsed, errParse := time.ParseDuration(ttl); errParse == nil && parsed > 0 {
			state.sessionAffinityTTL = parsed
		}
	}
	return state
}

func newRoutingSelector(state routingRuntimeState) coreauth.Selector {
	var selector coreauth.Selector
	switch state.strategy {
	case "weighted-round-robin":
		selector = &coreauth.WeightedRoundRobinSelector{}
	case "fill-first":
		selector = &coreauth.FillFirstSelector{}
	default:
		selector = &coreauth.RoundRobinSelector{}
	}
	if state.sessionAffinity {
		selector = coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
			Fallback: selector,
			TTL:      state.sessionAffinityTTL,
		})
	}
	return selector
}

func (s *Service) applyConfigUpdateWithAuthSynthesis(ctx context.Context, newCfg *config.Config, synthesizeConfigAuths bool) bool {
	commit := s.commitConfigUpdate(newCfg)
	if commit.cfg == nil {
		return false
	}
	return s.applyConfigRuntime(ctx, commit, synthesizeConfigAuths)
}

// commitConfigUpdate applies only in-memory configuration state. Runtime work that
// may block on plugins, models, storage, or networking is deliberately deferred.
func (s *Service) commitConfigUpdate(newCfg *config.Config) configCommit {
	if s == nil {
		return configCommit{}
	}

	s.configUpdateMu.Lock()
	defer s.configUpdateMu.Unlock()

	if newCfg == nil {
		s.cfgMu.RLock()
		newCfg = s.cfg
		s.cfgMu.RUnlock()
	}
	if newCfg == nil {
		return configCommit{}
	}
	if errValidate := newCfg.ValidateCredentialWeights(); errValidate != nil {
		log.WithError(errValidate).Warn("rejected config update with invalid credential weights")
		return configCommit{}
	}

	s.cfgMu.Lock()
	s.cfg = newCfg
	s.cfgMu.Unlock()
	s.configSequence++
	return configCommit{cfg: newCfg, sequence: s.configSequence}
}

func (s *Service) configCommitCurrent(commit configCommit) bool {
	if s == nil || commit.sequence == 0 {
		return false
	}
	s.configUpdateMu.Lock()
	current := s.configSequence == commit.sequence
	s.configUpdateMu.Unlock()
	return current
}

func (s *Service) applyConfigRuntime(ctx context.Context, commit configCommit, synthesizeConfigAuths bool) bool {
	cfg := commit.cfg
	if s == nil || cfg == nil {
		return false
	}
	reloadStarted := time.Now()
	s.configRuntimeMu.Lock()
	defer s.configRuntimeMu.Unlock()
	if !s.configCommitCurrent(commit) {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	if !s.applyManagerConfig(ctx, commit) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if !s.applyPprofConfigContext(ctx, cfg) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if !s.updateServerClientsContext(ctx, cfg) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	registrationCtx := coreauth.WithSkipPersist(ctx)
	s.syncPluginRuntimeConfigForConfig(registrationCtx, cfg)
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	var authSnapshots []coreauth.ExecutorRegistrationAuthSnapshot
	if s.coreManager != nil {
		authSnapshots = s.coreManager.ExecutorRegistrationSnapshot()
	}
	executorStats := s.registerAvailableExecutors(registrationCtx, executorRegistrationOptions{
		includeBaseline:   cfg.Home.Enabled,
		forceReplaceAuths: true,
		authSnapshots:     authSnapshots,
	})
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if synthesizeConfigAuths {
		s.registerConfigAPIKeyAuths(registrationCtx, cfg)
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if s.coreManager != nil && !cfg.Home.Enabled && cfg.SaveCooldownStatus {
		if errRestoreCooldown := s.coreManager.RestoreCooldownStates(registrationCtx); errRestoreCooldown != nil && ctx.Err() == nil {
			log.Warnf("failed to restore cooldown state after config update: %v", errRestoreCooldown)
		}
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	pluginStats := s.syncPluginModelRuntime(registrationCtx)
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	log.WithFields(log.Fields{
		"config_sequence":                       commit.sequence,
		"synthesize_config_auths":               synthesizeConfigAuths,
		"auth_count":                            pluginStats.modelAuthCount,
		"provider_count":                        pluginStats.executorRegistration.providerCount,
		"executor_auth_count":                   executorStats.authCount,
		"executor_registration_candidate_count": executorStats.registrationCount,
		"executor_deduplicated_auth_count":      executorStats.duplicateCount,
		"executor_disabled_auth_count":          executorStats.disabledCount,
		"post_sync_executor_candidate_count":    pluginStats.executorRegistration.registrationCount,
		"post_sync_deduplicated_auth_count":     pluginStats.executorRegistration.duplicateCount,
		"post_sync_disabled_auth_count":         pluginStats.executorRegistration.disabledCount,
		"config_runtime_reload_duration_millis": time.Since(reloadStarted).Milliseconds(),
	}).Info("config runtime reload completed")
	return true
}

func (s *Service) applyCredentialConfigRuntime(ctx context.Context, commit configCommit) bool {
	if s == nil || commit.cfg == nil {
		return false
	}
	reloadStarted := time.Now()
	s.configRuntimeMu.Lock()
	defer s.configRuntimeMu.Unlock()
	if !s.configCommitCurrent(commit) {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	// The watcher admits this path only when APIKeyEntries changed. The emitted
	// auth updates carry key, proxy, weight, and disabled state; manager policy,
	// routing, models, plugins, and retry settings therefore stay valid.
	if !s.updateServerCredentialConfigContext(ctx, commit.cfg) {
		return false
	}
	log.WithFields(log.Fields{
		"config_sequence":                   commit.sequence,
		"credential_reload_duration_millis": time.Since(reloadStarted).Milliseconds(),
	}).Info("credential-only config runtime reload completed")
	return true
}

func (s *Service) applyManagerConfig(ctx context.Context, commit configCommit) bool {
	if s == nil || s.coreManager == nil || commit.cfg == nil {
		return s != nil && commit.cfg != nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	routingState := normalizedRoutingRuntimeState(commit.cfg)
	if s.appliedRoutingState == nil || *s.appliedRoutingState != routingState {
		s.coreManager.SetSelector(newRoutingSelector(routingState))
		s.appliedRoutingState = &routingState
	}
	s.applyRetryConfig(commit.cfg)
	store := s.resolveCooldownStateStore(commit.cfg)
	if !s.coreManager.ApplyConfigWithCooldownStateStore(ctx, commit.cfg, store) {
		return false
	}
	s.coreManager.SetOAuthModelAlias(commit.cfg.OAuthModelAlias)
	return true
}

func (s *Service) updateServerClientsContext(ctx context.Context, cfg *config.Config) bool {
	if s == nil || cfg == nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	if s.updateServerClientsContextFn != nil {
		return s.updateServerClientsContextFn(ctx, cfg)
	}
	if s.server == nil {
		return true
	}
	return s.server.UpdateClientsContext(ctx, cfg)
}

func (s *Service) updateServerCredentialConfigContext(ctx context.Context, cfg *config.Config) bool {
	if s == nil || cfg == nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	if s.updateServerCredentialConfigContextFn != nil {
		return s.updateServerCredentialConfigContextFn(ctx, cfg)
	}
	if s.server == nil {
		return true
	}
	return s.server.UpdateCredentialEntriesContext(ctx, cfg)
}

func (s *Service) reloadConfigFromWatcher() bool {
	if s == nil || s.watcher == nil {
		return false
	}
	return s.watcher.ReloadConfigIfChanged()
}

func (s *Service) registerConfigAPIKeyAuths(ctx context.Context, cfg *config.Config) {
	if s == nil || s.coreManager == nil || cfg == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	configSynth := synthesizer.NewConfigSynthesizer()
	auths, errSynthesize := configSynth.Synthesize(&synthesizer.SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if errSynthesize != nil {
		log.Warnf("failed to synthesize config API key auths: %v", errSynthesize)
		return
	}

	registrationCtx := coreauth.WithDeferredAPIKeyModelAliasRebuild(ctx)
	tasks := make([]modelRegistrationTask, 0, len(auths))
	needsAliasRebuild := false
	for _, auth := range auths {
		if !coreauth.IsConfigAPIKeyAuth(auth) {
			continue
		}
		prepared := s.prepareCoreAuthForModelRegistration(registrationCtx, auth)
		if prepared == nil {
			continue
		}
		needsAliasRebuild = true
		authForRegistration := prepared
		tasks = append(tasks, modelRegistrationTask{
			phase:    modelRegistrationPhaseConfigAPIKey,
			category: modelRegistrationCategory(authForRegistration),
			run: func(compatCache *openAICompatibilityRegistrationCache) {
				s.completeModelRegistrationForAuthWithCache(registrationCtx, authForRegistration, compatCache)
			},
		})
	}
	if needsAliasRebuild {
		s.coreManager.RefreshAPIKeyModelAlias()
	}
	s.runModelRegistrationTasks(registrationCtx, tasks)
}

func forceHomeRuntimeConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	cfg.APIKeys = nil
	cfg.UsageStatisticsEnabled = true
	cfg.DisableCooling = true
	cfg.SaveCooldownStatus = false
	cfg.WebsocketAuth = false
	cfg.RemoteManagement.AllowRemote = false
	cfg.RemoteManagement.DisableControlPanel = true
	cfg.Plugins.StoreAuth = nil
}
