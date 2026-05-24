package config

import "testing"

func TestParserNestedServerAndUpstream(t *testing.T) {
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

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("ParseMapping error: %v", err)
	}

	upstreamNode := node.Get("upstream")
	if upstreamNode == nil {
		t.Fatal("expected 'upstream' node")
	}
	if upstreamNode.Type != NodeMapping {
		t.Errorf("expected upstream to be Mapping, got %v", upstreamNode.Type)
	}
	if strategy := upstreamNode.GetString("strategy"); strategy != "round_robin" {
		t.Errorf("expected strategy round_robin, got %q", strategy)
	}
	serversNode := upstreamNode.Get("servers")
	if serversNode == nil || serversNode.Type != NodeSequence {
		t.Fatal("expected upstream.servers sequence")
	}
}
