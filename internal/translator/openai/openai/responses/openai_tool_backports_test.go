package responses

import (
	"reflect"
	"testing"

	"github.com/tidwall/gjson"
)

func TestResponsesToolHistoryAlignmentBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		roles []string
	}{
		{"complete", `[{"type":"function_call","call_id":"a","name":"echo","arguments":"{}"},{"role":"user","content":"reminder"},{"type":"function_call_output","call_id":"a","output":"ok"}]`, []string{"assistant", "tool", "user"}},
		{"incomplete parallel calls", `[{"type":"function_call","call_id":"a","name":"echo","arguments":"{}"},{"type":"function_call","call_id":"b","name":"echo","arguments":"{}"},{"role":"user","content":"reminder"},{"type":"function_call_output","call_id":"a","output":"ok"}]`, []string{"assistant", "user", "tool"}},
		{"duplicate outputs", `[{"type":"function_call","call_id":"a","name":"echo","arguments":"{}"},{"role":"user","content":"reminder"},{"type":"function_call_output","call_id":"a","output":"first"},{"type":"function_call_output","call_id":"a","output":"second"}]`, []string{"assistant", "user", "tool", "tool"}},
		{"missing output ID", `[{"type":"function_call","call_id":"a","name":"echo","arguments":"{}"},{"role":"user","content":"reminder"},{"type":"function_call_output","output":"orphan"}]`, []string{"assistant", "user", "tool"}},
		{"custom tools", `[{"type":"custom_tool_call","call_id":"a","name":"patch","input":"text"},{"role":"user","content":"reminder"},{"type":"custom_tool_call_output","call_id":"a","output":"ok"}]`, []string{"assistant", "tool", "user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := ConvertOpenAIResponsesRequestToOpenAIChatCompletions("test-model", []byte(`{"input":`+tt.input+`}`), false)
			var roles []string
			for _, message := range gjson.GetBytes(out, "messages").Array() {
				roles = append(roles, message.Get("role").String())
			}
			if !reflect.DeepEqual(roles, tt.roles) {
				t.Fatalf("roles = %v, want %v; output=%s", roles, tt.roles, out)
			}
		})
	}
}

func TestResponsesNamedToolChoiceIdentityBoundaries(t *testing.T) {
	tests := []struct {
		name, tools, input, choice, want string
	}{
		{"ambiguous bare name", `[{"type":"namespace","name":"first","tools":[{"type":"function","name":"echo"}]},{"type":"namespace","name":"second","tools":[{"type":"function","name":"echo"}]}]`, `"hi"`, `{"type":"function","name":"echo"}`, "echo"},
		{"explicit qualified name", `[{"type":"namespace","name":"first","tools":[{"type":"function","name":"echo"}]}]`, `"hi"`, `{"type":"function","name":"first__echo"}`, "first__echo"},
		{"additional tools", `[]`, `[{"type":"additional_tools","tools":[{"type":"namespace","name":"extra","tools":[{"type":"custom","name":"patch"}]}]},{"role":"user","content":"hi"}]`, `{"type":"custom","name":"patch"}`, "extra__patch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := ConvertOpenAIResponsesRequestToOpenAIChatCompletions("test-model", []byte(`{"tools":`+tt.tools+`,"input":`+tt.input+`,"tool_choice":`+tt.choice+`}`), false)
			if got := gjson.GetBytes(out, "tool_choice.function.name").String(); got != tt.want {
				t.Fatalf("tool choice = %q, want %q; output=%s", got, tt.want, out)
			}
		})
	}
}
