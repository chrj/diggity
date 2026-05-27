package version

import "testing"

func TestStringUsesExplicitVersion(t *testing.T) {
	orig := Version
	Version = "1.2.3"
	defer func() { Version = orig }()

	if got, want := String(), "diggity 1.2.3"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
