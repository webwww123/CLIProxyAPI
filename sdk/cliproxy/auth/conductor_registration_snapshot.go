package auth

// ExecutorRegistrationAuthSnapshot contains only the auth fields used to bind provider executors.
type ExecutorRegistrationAuthSnapshot struct {
	ID                string
	Provider          string
	Label             string
	Disabled          bool
	BaseURL           string
	CompatibilityName string
	ProviderKey       string
}

// ExecutorRegistrationSnapshot returns lightweight auth projections for executor binding.
func (m *Manager) ExecutorRegistrationSnapshot() []ExecutorRegistrationAuthSnapshot {
	if m == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ExecutorRegistrationAuthSnapshot, 0, len(m.auths))
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		snapshot := ExecutorRegistrationAuthSnapshot{
			ID:       auth.ID,
			Provider: auth.Provider,
			Label:    auth.Label,
			Disabled: auth.Disabled,
		}
		if auth.Attributes != nil {
			snapshot.BaseURL = auth.Attributes["base_url"]
			snapshot.CompatibilityName = auth.Attributes["compat_name"]
			snapshot.ProviderKey = auth.Attributes["provider_key"]
		}
		out = append(out, snapshot)
	}
	return out
}

// ModelRegistrationSnapshot returns isolated auth copies without per-model runtime state.
func (m *Manager) ModelRegistrationSnapshot() []*Auth {
	if m == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Auth, 0, len(m.auths))
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		out = append(out, cloneAuthWithoutModelStates(auth))
	}
	return out
}

func cloneAuthWithoutModelStates(auth *Auth) *Auth {
	if auth == nil {
		return nil
	}
	copyAuth := *auth
	if len(auth.Attributes) > 0 {
		copyAuth.Attributes = make(map[string]string, len(auth.Attributes))
		for key, value := range auth.Attributes {
			copyAuth.Attributes[key] = value
		}
	}
	if len(auth.Metadata) > 0 {
		copyAuth.Metadata = make(map[string]any, len(auth.Metadata))
		for key, value := range auth.Metadata {
			copyAuth.Metadata[key] = value
		}
	}
	copyAuth.ModelStates = nil
	copyAuth.Runtime = auth.Runtime
	return &copyAuth
}
