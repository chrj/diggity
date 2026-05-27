package dnsutil

import "testing"

func TestParentName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{"www.example.com", "example.com.", true},
		{"example.com.", "com.", true},
		{"com.", ".", true},
		{".", "", false},
	}

	for _, tt := range tests {
		got, ok := ParentName(tt.name)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("ParentName(%q) = (%q, %v), want (%q, %v)", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestTrimDot(t *testing.T) {
	t.Parallel()

	if got := TrimDot("example.com."); got != "example.com" {
		t.Fatalf("TrimDot() = %q, want %q", got, "example.com")
	}
	if got := TrimDot("example.com"); got != "example.com" {
		t.Fatalf("TrimDot() without dot = %q, want unchanged", got)
	}
}
