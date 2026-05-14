package main

import (
	"slices"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace", in: "  \t ", want: nil},
		{name: "single", in: "curve25519-sha256", want: []string{"curve25519-sha256"}},
		{name: "trims and skips empty", in: " aes128-ctr, ,aes256-ctr ,, ", want: []string{"aes128-ctr", "aes256-ctr"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitCSV(tc.in); !slices.Equal(got, tc.want) {
				t.Fatalf("splitCSV(%q) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}
