package helps

import (
	"strings"
	"unicode"

	"github.com/tidwall/gjson"
)

const maxResponseModelLength = 128

// ObserveResponseModel records only upstream metadata; it never changes model
// mapping, public aliases, routing decisions, or client response payloads.
func (r *UsageReporter) ObserveResponseModel(payload []byte) {
	if r == nil {
		return
	}
	data := jsonPayload(payload)
	if !gjson.ValidBytes(data) {
		return
	}
	root := gjson.ParseBytes(data)
	eventType := root.Get("type").String()
	terminal := eventType == "response.completed" || eventType == "response.done" || eventType == "response.incomplete" || eventType == "response.failed" ||
		root.Get("object").String() == "chat.completion" || root.Get("choices.0.finish_reason").String() != "" ||
		root.Get("status").String() == "completed" || root.Get("status").String() == "incomplete"
	model := ""
	for _, path := range []string{"response.model", "model", "message.model"} {
		value := root.Get(path)
		if value.Type != gjson.String {
			continue
		}
		candidate := strings.TrimSpace(value.String())
		if candidate != "" && len(candidate) <= maxResponseModelLength && strings.IndexFunc(candidate, unicode.IsControl) < 0 {
			model = candidate
			break
		}
	}
	r.responseModelMu.Lock()
	defer r.responseModelMu.Unlock()
	if r.responseModelFinal {
		return
	}
	if model != "" {
		r.responseModel = model
	}
	if terminal {
		r.responseModelFinal = true
	}
}

func (r *UsageReporter) ResponseModel() string {
	if r == nil {
		return ""
	}
	r.responseModelMu.RLock()
	defer r.responseModelMu.RUnlock()
	return r.responseModel
}

func (r *UsageReporter) IsResponseModelFinal() bool {
	if r == nil {
		return false
	}
	r.responseModelMu.RLock()
	defer r.responseModelMu.RUnlock()
	return r.responseModelFinal
}
