package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]struct{}
		wantErr bool
	}{
		{name: "names", input: `["a","b","a"]`, want: map[string]struct{}{"a": {}, "b": {}}},
		{name: "empty", input: `[]`, want: map[string]struct{}{}},
		{name: "null", input: `null`, wantErr: true},
		{name: "object", input: `{"params":["a"]}`, wantErr: true},
		{name: "non-string", input: `["a",null]`, wantErr: true},
		{name: "malformed", input: `[`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowlist([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAllowlist() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAllowlist() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		allowed map[string]struct{}
		want    string
	}{
		{
			name:    "preserves repeated values and order",
			query:   "keep=one&drop=x&keep=two&flag&empty=",
			allowed: map[string]struct{}{"keep": {}, "flag": {}, "empty": {}},
			want:    "keep=one&keep=two&flag&empty=",
		},
		{
			name:    "matches decoded names without rewriting values",
			query:   "a%20b=x%2By&a+b=two&drop=1",
			allowed: map[string]struct{}{"a b": {}},
			want:    "a%20b=x%2By&a+b=two",
		},
		{name: "empty allowlist", query: "a=1&b=2", allowed: map[string]struct{}{}, want: ""},
		{name: "no match", query: "drop=1", allowed: map[string]struct{}{"keep": {}}, want: ""},
		{name: "empty query", query: "", allowed: map[string]struct{}{}, want: ""},
		{
			name:    "malformed escapes are treated literally",
			query:   "bad%zz=1&bad%2=2&keep=3",
			allowed: map[string]struct{}{"bad%zz": {}, "bad%2": {}},
			want:    "bad%zz=1&bad%2=2",
		},
		{name: "empty names are ignored", query: "=value&keep=1", allowed: map[string]struct{}{"": {}, "keep": {}}, want: "keep=1"},
		{
			name:    "beyond one hundred parameters",
			query:   strings.Repeat("drop=1&", 150) + "keep=last",
			allowed: map[string]struct{}{"keep": {}},
			want:    "keep=last",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterQuery(tt.query, tt.allowed)
			if got != tt.want {
				t.Errorf("filterQuery() = %q, want %q", got, tt.want)
			}
		})
	}
}
