package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type managementCredentialPolicyExecutor struct {
	provider string
}

func (e *managementCredentialPolicyExecutor) Identifier() string { return e.provider }
func (e *managementCredentialPolicyExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{Payload: []byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)}, nil
}
func (e *managementCredentialPolicyExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e *managementCredentialPolicyExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}
func (e *managementCredentialPolicyExecutor) CountTokens(ctx context.Context, auth *coreauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}
func (e *managementCredentialPolicyExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestCredentialPolicyManagementStatusManualRecoveryAndAuthList(t *testing.T) {
	provider := util.OpenAICompatibleProviderKey("mistral")
	disableCooling := false
	cfg := &config.Config{
		AuthDir: t.TempDir(),
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:           "mistral",
			BaseURL:        "https://api.mistral.ai/v1",
			DisableCooling: &disableCooling,
			CredentialPolicy: &config.OpenAICompatibilityCredentialPolicy{
				ScopeStatuses:            []int{http.StatusPaymentRequired},
				InitialCooldownSeconds:   60,
				MaxCooldownSeconds:       3600,
				BackoffFactor:            2,
				ManualTestConcurrency:    1,
				ManualTestMaxModels:      1,
				ManualTestTimeoutSeconds: 5,
			},
			Models: []config.OpenAICompatibilityModel{{Name: "mistral-small-latest", Alias: "test-model"}},
		}},
	}
	cfg.SanitizeOpenAICompatibility()
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.RegisterExecutor(&managementCredentialPolicyExecutor{provider: provider})
	next := time.Now().Add(time.Hour)
	auth := &coreauth.Auth{
		ID:             "management-policy-auth",
		Provider:       provider,
		Status:         coreauth.StatusError,
		StatusMessage:  "credential policy cooldown",
		Unavailable:    true,
		NextRetryAfter: next,
		Quota: coreauth.QuotaState{
			Exceeded:      true,
			Reason:        "provider_credential_policy",
			NextRecoverAt: next,
			BackoffLevel:  2,
		},
		LastError: &coreauth.Error{HTTPStatus: http.StatusPaymentRequired, Message: "provider credential policy failure"},
		UpdatedAt: time.Now(),
		Attributes: map[string]string{
			coreauth.AttributeConfigIndex: "0",
			"compat_name":                 "mistral",
			"provider_key":                provider,
			"runtime_only":                "true",
		},
	}
	authIndex := auth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	h := NewHandlerWithoutConfigFilePath(cfg, manager)

	statusRec := httptest.NewRecorder()
	statusCtx, _ := gin.CreateTestContext(statusRec)
	statusCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/credential-policy/status?provider=mistral", nil)
	h.GetCredentialPolicyStatus(statusCtx)
	if statusRec.Code != http.StatusOK || !strings.Contains(statusRec.Body.String(), authIndex) || strings.Contains(statusRec.Body.String(), auth.ID) {
		t.Fatalf("status response = %d %s", statusRec.Code, statusRec.Body.String())
	}

	listRec := httptest.NewRecorder()
	listCtx, _ := gin.CreateTestContext(listRec)
	listCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(listCtx)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), "credential_policy") || !strings.Contains(listRec.Body.String(), "credential_ref") {
		t.Fatalf("auth list response = %d %s", listRec.Code, listRec.Body.String())
	}

	testRec := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(testRec)
	body, _ := json.Marshal(map[string]string{"provider": "mistral", "auth_index": authIndex})
	testCtx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/credential-policy/test-cooling", strings.NewReader(string(body)))
	testCtx.Request.Header.Set("Content-Type", "application/json")
	h.TestCoolingCredentials(testCtx)
	if testRec.Code != http.StatusOK || !strings.Contains(testRec.Body.String(), `"recovered":1`) {
		t.Fatalf("manual test response = %d %s", testRec.Code, testRec.Body.String())
	}
	updated, _ := manager.GetByID(auth.ID)
	if updated == nil || updated.Quota.Exceeded || updated.Unavailable {
		t.Fatalf("manual management recovery did not clear policy state: %+v", updated)
	}
	healthyRec := httptest.NewRecorder()
	healthyCtx, _ := gin.CreateTestContext(healthyRec)
	healthyCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/credential-policy/status?provider=mistral", nil)
	h.GetCredentialPolicyStatus(healthyCtx)
	if healthyRec.Code != http.StatusOK || !strings.Contains(healthyRec.Body.String(), `"healthy":1`) || !strings.Contains(healthyRec.Body.String(), `"state":"healthy"`) {
		t.Fatalf("healthy status response = %d %s", healthyRec.Code, healthyRec.Body.String())
	}
}
