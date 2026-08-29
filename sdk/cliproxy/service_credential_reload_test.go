package cliproxy

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestApplyWatcherCredentialConfigUpdateSkipsFullRuntime(t *testing.T) {
	oldCfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{{
		Name:          "provider-a",
		BaseURL:       "https://example.com/v1",
		Models:        []config.OpenAICompatibilityModel{{Name: "model", Alias: "model"}},
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "key-a"}},
	}}}
	newCfg := oldCfg.CloneForRuntime()
	newCfg.OpenAICompatibility[0].APIKeyEntries[0].ProxyURL = "http://proxy-new"

	fullPprofCalls := 0
	fullServerCalls := 0
	credentialServerCalls := 0
	service := &Service{cfg: oldCfg}
	service.applyPprofConfigContextFn = func(context.Context, *config.Config) bool {
		fullPprofCalls++
		return true
	}
	service.updateServerClientsContextFn = func(context.Context, *config.Config) bool {
		fullServerCalls++
		return true
	}
	service.updateServerCredentialConfigContextFn = func(_ context.Context, cfg *config.Config) bool {
		credentialServerCalls++
		return cfg == newCfg
	}

	if !service.applyWatcherCredentialConfigUpdate(newCfg) {
		t.Fatal("credential-only config update failed")
	}
	if service.cfg != newCfg {
		t.Fatal("credential-only config update did not commit the new config")
	}
	if credentialServerCalls != 1 || fullPprofCalls != 0 || fullServerCalls != 0 {
		t.Fatalf("runtime calls = credential:%d pprof:%d full-server:%d, want 1/0/0", credentialServerCalls, fullPprofCalls, fullServerCalls)
	}
}

func TestServiceHandleAuthUpdatesPreservesUnrelatedRuntimeState(t *testing.T) {
	tests := []struct {
		name   string
		action watcher.AuthUpdateAction
		setup  func(*testing.T, *Service, *coreauth.Auth)
	}{
		{name: "add", action: watcher.AuthUpdateActionAdd, setup: func(*testing.T, *Service, *coreauth.Auth) {}},
		{
			name:   "modify",
			action: watcher.AuthUpdateActionModify,
			setup: func(t *testing.T, service *Service, auth *coreauth.Auth) {
				if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
					t.Fatalf("register updated auth: %v", errRegister)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, otherID, modelID := newServiceWithErroredAuth(t)
			target := credentialReloadXAIAuth("xai-updated-auth.json")
			tt.setup(t, service, target)

			service.handleAuthUpdates(context.Background(), []watcher.AuthUpdate{{
				Action: tt.action,
				ID:     target.ID,
				Auth:   target,
			}})

			if _, ok := service.coreManager.GetByID(target.ID); !ok {
				t.Fatalf("updated auth %q was not registered", target.ID)
			}
			assertErroredAuthUnchanged(t, service.coreManager, otherID, modelID)
		})
	}
}

func TestServiceApplyCoreAuthRemovalPreservesUnrelatedRuntimeState(t *testing.T) {
	service, otherID, modelID := newServiceWithErroredAuth(t)
	target := credentialReloadXAIAuth("xai-removed-auth.json")
	if _, errRegister := service.coreManager.Register(context.Background(), target); errRegister != nil {
		t.Fatalf("register removed auth: %v", errRegister)
	}
	service.registerModelsForAuth(context.Background(), target)

	service.applyCoreAuthRemoval(context.Background(), target.ID)

	if _, ok := service.coreManager.GetByID(target.ID); ok {
		t.Fatalf("removed auth %q is still registered", target.ID)
	}
	if models := registry.GetGlobalRegistry().GetModelsForClient(target.ID); len(models) != 0 {
		t.Fatalf("removed auth %q still has %d registered models", target.ID, len(models))
	}
	assertErroredAuthUnchanged(t, service.coreManager, otherID, modelID)
}

func newServiceWithErroredAuth(t *testing.T) (*Service, string, string) {
	t.Helper()
	models := registry.GetXAIModels()
	if len(models) == 0 || models[0] == nil || models[0].ID == "" {
		t.Fatal("xAI model catalog is empty")
	}

	modelID := models[0].ID
	other := credentialReloadXAIAuth("xai-errored-auth.json")
	retryAfter := time.Now().Add(time.Hour)
	other.Status = coreauth.StatusError
	other.StatusMessage = "upstream timeout"
	other.Unavailable = true
	other.LastError = &coreauth.Error{
		Code:       "upstream_error",
		Message:    "upstream timeout",
		HTTPStatus: http.StatusServiceUnavailable,
	}
	other.NextRetryAfter = retryAfter
	other.ModelStates = map[string]*coreauth.ModelState{
		modelID: {
			Status:         coreauth.StatusError,
			StatusMessage:  "upstream timeout",
			Unavailable:    true,
			LastError:      &coreauth.Error{Code: "upstream_error", Message: "upstream timeout", HTTPStatus: http.StatusServiceUnavailable},
			NextRetryAfter: retryAfter,
			Quota: coreauth.QuotaState{
				Exceeded:      true,
				Reason:        "quota",
				NextRecoverAt: retryAfter,
				BackoffLevel:  2,
			},
		},
	}

	manager := coreauth.NewManager(nil, nil, nil)
	if _, errRegister := manager.Register(context.Background(), other); errRegister != nil {
		t.Fatalf("register errored auth: %v", errRegister)
	}
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(other.ID)
		GlobalModelRegistry().UnregisterClient("xai-updated-auth.json")
		GlobalModelRegistry().UnregisterClient("xai-removed-auth.json")
		sdktranslator.SetPluginHooks(nil)
	})

	return &Service{
		cfg:         &config.Config{},
		coreManager: manager,
		pluginHost:  pluginhost.New(),
	}, other.ID, modelID
}

func credentialReloadXAIAuth(id string) *coreauth.Auth {
	return &coreauth.Auth{
		ID:       id,
		Provider: "xai",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"type": "xai"},
	}
}

func assertErroredAuthUnchanged(t *testing.T, manager *coreauth.Manager, authID, modelID string) {
	t.Helper()
	got, ok := manager.GetByID(authID)
	if !ok || got == nil {
		t.Fatalf("errored auth %q disappeared", authID)
	}
	if got.Status != coreauth.StatusError || got.StatusMessage != "upstream timeout" || !got.Unavailable {
		t.Fatalf("auth runtime state changed: %+v", got)
	}
	if got.LastError == nil || got.LastError.Message != "upstream timeout" || got.NextRetryAfter.Before(time.Now()) {
		t.Fatalf("auth error/cooldown changed: error=%+v retry=%v", got.LastError, got.NextRetryAfter)
	}
	state := got.ModelStates[modelID]
	if state == nil {
		t.Fatalf("model state %q disappeared", modelID)
	}
	if state.Status != coreauth.StatusError || state.StatusMessage != "upstream timeout" || !state.Unavailable {
		t.Fatalf("model runtime state changed: %+v", state)
	}
	if state.LastError == nil || state.LastError.Message != "upstream timeout" || state.NextRetryAfter.Before(time.Now()) {
		t.Fatalf("model error/cooldown changed: error=%+v retry=%v", state.LastError, state.NextRetryAfter)
	}
	if !state.Quota.Exceeded || state.Quota.Reason != "quota" || state.Quota.BackoffLevel != 2 {
		t.Fatalf("model quota changed: %+v", state.Quota)
	}
}
