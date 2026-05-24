package config

import "testing"

func TestParserSkipsComments(t *testing.T) {
	input := `# This is a comment
key: value # inline comment
# Another comment`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if value := node.GetString("key"); value != "value" {
		t.Fatalf("expected key value, got %q", value)
	}
}
