package delegation

import (
	"reflect"
	"testing"
)

func TestInBailiwick(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ns   string
		zone string
		want bool
	}{
		{"ns1.example.com.", "example.com.", true},
		{"example.com.", "example.com.", true},
		{"ns1.other.com.", "example.com.", false},
		{"anything.", ".", true},
	}

	for _, tt := range tests {
		if got := inBailiwick(tt.ns, tt.zone); got != tt.want {
			t.Fatalf("inBailiwick(%q, %q) = %v, want %v", tt.ns, tt.zone, got, tt.want)
		}
	}
}

func TestSetHelpers(t *testing.T) {
	t.Parallel()

	if got, want := normaliseSet([]string{"NS2.EXAMPLE.COM", "ns1.example.com.", "ns2.example.com."}), []string{"ns1.example.com.", "ns2.example.com."}; !reflect.DeepEqual(got, want) {
		t.Fatalf("normaliseSet() = %#v, want %#v", got, want)
	}

	gotUnion := unionSet(map[string][]string{
		"a": {"ns2.example.com.", "ns1.example.com."},
		"b": {"ns1.example.com.", "ns3.example.com."},
	})
	wantUnion := []string{"ns1.example.com.", "ns2.example.com.", "ns3.example.com."}
	if !reflect.DeepEqual(gotUnion, wantUnion) {
		t.Fatalf("unionSet() = %#v, want %#v", gotUnion, wantUnion)
	}

	if !equalSets([]string{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("equalSets() = false, want true")
	}
	if equalSets([]string{"a"}, []string{"b"}) {
		t.Fatal("equalSets() = true, want false")
	}

	if got, want := diffSets([]string{"a", "b", "c"}, []string{"b"}), []string{"a", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("diffSets() = %#v, want %#v", got, want)
	}
	if got, want := stripDots([]string{"a.", "b."}), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stripDots() = %#v, want %#v", got, want)
	}
}
