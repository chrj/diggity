package ttl

import (
	"reflect"
	"testing"
)

func TestTTLHelpers(t *testing.T) {
	t.Parallel()

	if got, want := uniqueSorted([]uint32{300, 60, 300, 120}), []uint32{60, 120, 300}; !reflect.DeepEqual(got, want) {
		t.Fatalf("uniqueSorted() = %#v, want %#v", got, want)
	}
	if got, want := formatTTLs([]uint32{60, 3600}), "1m0s, 1h0m0s"; got != want {
		t.Fatalf("formatTTLs() = %q, want %q", got, want)
	}
	if got, want := appendUnique([]uint16{1, 2}, 2), []uint16{1, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("appendUnique(existing) = %#v, want %#v", got, want)
	}
	if got, want := appendUnique([]uint16{1, 2}, 3), []uint16{1, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("appendUnique(new) = %#v, want %#v", got, want)
	}
}
