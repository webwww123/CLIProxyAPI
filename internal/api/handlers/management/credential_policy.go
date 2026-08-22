package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// GetCredentialPolicyStatus lists secret-safe cooling and eligible penalty state.
func (h *Handler) GetCredentialPolicyStatus(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	statuses, errStatus := h.authManager.ProviderCredentialPolicyStatuses(strings.TrimSpace(c.Query("provider")))
	if errStatus != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errStatus.Error()})
		return
	}
	items := make([]gin.H, 0, len(statuses))
	cooling := 0
	eligible := 0
	healthy := 0
	for _, status := range statuses {
		item := credentialPolicyStatusEntry(status)
		if auth, ok := h.authManager.GetByID(status.AuthID); ok && auth != nil {
			item["auth_index"] = lockedAuthIndex(auth)
		}
		items = append(items, item)
		if status.State == "cooling" {
			cooling++
		} else if status.State == "eligible" {
			eligible++
		} else if status.State == "healthy" {
			healthy++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"cooling":  cooling,
		"eligible": eligible,
		"healthy":  healthy,
		"items":    items,
	})
}

// TestCoolingCredentials directly tests one or all cooling credentials for a provider.
func (h *Handler) TestCoolingCredentials(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Provider  string `json:"provider"`
		AuthIndex string `json:"auth_index"`
		Model     string `json:"model"`
	}
	if errBindJSON := c.ShouldBindJSON(&req); errBindJSON != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	provider := strings.TrimSpace(req.Provider)
	authIDs := make([]string, 0, 1)
	if authIndex := strings.TrimSpace(req.AuthIndex); authIndex != "" {
		auth := h.authByIndex(authIndex)
		if auth == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
			return
		}
		authIDs = append(authIDs, auth.ID)
		if provider == "" {
			provider = auth.Provider
		}
	}
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider is required when auth_index is omitted"})
		return
	}

	results, errTest := h.authManager.TestCoolingProviderCredentials(c.Request.Context(), coreauth.ProviderCredentialManualTestOptions{
		Provider: provider,
		AuthIDs:  authIDs,
		Model:    strings.TrimSpace(req.Model),
	})
	if errTest != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errTest.Error()})
		return
	}

	items := make([]gin.H, 0, len(results))
	succeeded := 0
	recovered := 0
	for _, result := range results {
		item := gin.H{
			"provider":       result.Provider,
			"credential_ref": result.CredentialRef,
			"model":          result.Model,
			"http_status":    result.HTTPStatus,
			"success":        result.Success,
			"recovered":      result.Recovered,
			"state":          result.State,
		}
		if result.ErrorCode != "" {
			item["error_code"] = result.ErrorCode
		}
		if auth, ok := h.authManager.GetByID(result.AuthID); ok && auth != nil {
			item["auth_index"] = lockedAuthIndex(auth)
		}
		items = append(items, item)
		if result.Success {
			succeeded++
		}
		if result.Recovered {
			recovered++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"tested":    len(results),
		"succeeded": succeeded,
		"recovered": recovered,
		"results":   items,
	})
}

func credentialPolicyStatusEntry(status coreauth.ProviderCredentialPolicyStatus) gin.H {
	entry := gin.H{
		"provider":       status.Provider,
		"credential_ref": status.CredentialRef,
		"state":          status.State,
		"backoff_level":  status.BackoffLevel,
	}
	if status.LastHTTPStatus > 0 {
		entry["last_http_status"] = status.LastHTTPStatus
	}
	if !status.NextRetryAfter.IsZero() {
		entry["return_at"] = status.NextRetryAfter
	}
	if !status.StateUpdatedAt.IsZero() {
		entry["state_updated_at"] = status.StateUpdatedAt
	}
	return entry
}
