package config

import "testing"

func TestUnmarshalYAMLBasicServerAndUpstream(t *testing.T) {
	input := `
server:
  port: 5353
  bind:
    - 127.0.0.1
upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
`

	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()
	if len(tokens) == 0 {
		t.Fatal("expected tokenizer to return tokens")
	}

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Server.Port)
	}
	if len(cfg.Server.Bind) != 1 || cfg.Server.Bind[0] != "127.0.0.1" {
		t.Errorf("expected bind [127.0.0.1], got %v", cfg.Server.Bind)
	}
	if cfg.Upstream.Strategy != "round_robin" {
		t.Errorf("expected strategy 'round_robin', got %q", cfg.Upstream.Strategy)
	}
	if len(cfg.Upstream.Servers) != 2 {
		t.Errorf("expected 2 upstream servers, got %d", len(cfg.Upstream.Servers))
	}
}
