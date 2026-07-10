package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func qName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func TestUpstreamResponseMatchesQuestion(t *testing.T) {
	want := &protocol.Question{Name: qName(t, "www.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}

	tests := []struct {
		name string
		resp *protocol.Message
		ok   bool
	}{
		{
			name: "exact match",
			resp: &protocol.Message{Questions: []*protocol.Question{{Name: qName(t, "www.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}}},
			ok:   true,
		},
		{
			name: "case-insensitive name match",
			resp: &protocol.Message{Questions: []*protocol.Question{{Name: qName(t, "WWW.Example.COM."), QType: protocol.TypeA, QClass: protocol.ClassIN}}},
			ok:   true,
		},
		{
			name: "wrong name (spoof answering a different question)",
			resp: &protocol.Message{Questions: []*protocol.Question{{Name: qName(t, "evil.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}}},
			ok:   false,
		},
		{
			name: "wrong type",
			resp: &protocol.Message{Questions: []*protocol.Question{{Name: qName(t, "www.example.com."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}}},
			ok:   false,
		},
		{
			name: "no question section",
			resp: &protocol.Message{},
			ok:   false,
		},
		{
			name: "multiple questions",
			resp: &protocol.Message{Questions: []*protocol.Question{
				{Name: qName(t, "www.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
				{Name: qName(t, "other.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
			}},
			ok: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := upstreamResponseMatchesQuestion(tc.resp, want); got != tc.ok {
				t.Errorf("upstreamResponseMatchesQuestion = %v, want %v", got, tc.ok)
			}
		})
	}
}
