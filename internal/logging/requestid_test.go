package logging

import "testing"

func TestIsSafeRequestID(t *testing.T) {
	for _, value := range []string{"request-123", "req_abc.def:456", "A"} {
		if !IsSafeRequestID(value) {
			t.Fatalf("expected %q to be safe", value)
		}
	}
	for _, value := range []string{"", "contains space", "line\nbreak", "slash/value", string(make([]byte, 129))} {
		if IsSafeRequestID(value) {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
