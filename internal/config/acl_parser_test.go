package config

import "testing"

func TestUnmarshalYAMLACLRule(t *testing.T) {
	input := `
acl:
  - name: local
    networks:
      - "127.0.0.1/32"
      - "10.0.0.0/8"
    types:
      - A
      - AAAA
    action: allow
`

	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()
	if len(tokens) == 0 {
		t.Fatal("expected tokenizer to return tokens")
	}

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aclNode := node.Get("acl"); aclNode == nil || aclNode.Type != NodeSequence {
		t.Fatal("expected acl sequence node")
	}

	if len(cfg.ACL) != 1 {
		t.Errorf("expected 1 ACL rule, got %d", len(cfg.ACL))
	}
	if cfg.ACL[0].Name != "local" {
		t.Errorf("expected ACL name local, got %q", cfg.ACL[0].Name)
	}
}
