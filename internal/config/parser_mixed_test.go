package config

import "testing"

func TestParserMixedMappingAndSequences(t *testing.T) {
	input := `name: test
values:
  - a
  - b
  - c
config:
  enabled: true
  count: 42`

	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()
	if len(tokens) == 0 {
		t.Fatal("expected tokenizer to return tokens")
	}

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if name := node.GetString("name"); name != "test" {
		t.Errorf("expected name 'test', got %q", name)
	}

	valuesNode := node.Get("values")
	if valuesNode == nil || valuesNode.Type != NodeSequence {
		t.Error("expected 'values' to be a sequence")
	}

	configNode := node.Get("config")
	if configNode == nil || configNode.Type != NodeMapping {
		t.Error("expected 'config' to be a mapping")
	}
}
