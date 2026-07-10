package resolver

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func mkName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func aRR(t *testing.T, owner string, b byte) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: mkName(t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, b}}}
}
func cnameRR(t *testing.T, owner, target string) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: mkName(t, owner), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataCNAME{CName: mkName(t, target)}}
}

func owners(msg *protocol.Message) []string {
	var o []string
	for _, rr := range msg.Answers {
		o = append(o, rr.Name.String())
	}
	return o
}

func TestPruneAnswerToChain(t *testing.T) {
	t.Run("multi-A at qname preserved", func(t *testing.T) {
		msg := &protocol.Message{Answers: []*protocol.ResourceRecord{
			aRR(t, "www.example.com.", 1), aRR(t, "www.example.com.", 2),
		}}
		pruneAnswerToChain(msg, "www.example.com.", protocol.TypeA)
		if len(msg.Answers) != 2 {
			t.Errorf("multi-A answer pruned to %d, want 2 (%v)", len(msg.Answers), owners(msg))
		}
	})

	t.Run("CNAME chain preserved", func(t *testing.T) {
		msg := &protocol.Message{Answers: []*protocol.ResourceRecord{
			cnameRR(t, "www.example.com.", "web.example.com."),
			cnameRR(t, "web.example.com.", "host.example.net."),
			aRR(t, "host.example.net.", 5),
		}}
		pruneAnswerToChain(msg, "www.example.com.", protocol.TypeA)
		if len(msg.Answers) != 3 {
			t.Errorf("CNAME chain pruned to %d, want 3 (%v)", len(msg.Answers), owners(msg))
		}
	})

	t.Run("injected off-chain record dropped", func(t *testing.T) {
		msg := &protocol.Message{Answers: []*protocol.ResourceRecord{
			aRR(t, "www.example.com.", 1),
			aRR(t, "www.bank.com.", 66), // hostile injection
		}}
		pruneAnswerToChain(msg, "www.example.com.", protocol.TypeA)
		if len(msg.Answers) != 1 {
			t.Fatalf("expected injected record dropped, got %d answers (%v)", len(msg.Answers), owners(msg))
		}
		if msg.Answers[0].Name.String() != "www.example.com." {
			t.Errorf("wrong record kept: %s", msg.Answers[0].Name.String())
		}
	})

	t.Run("CNAME-chased injection dropped, chain kept", func(t *testing.T) {
		msg := &protocol.Message{Answers: []*protocol.ResourceRecord{
			cnameRR(t, "www.example.com.", "web.example.com."),
			aRR(t, "web.example.com.", 7),
			aRR(t, "evil.example.org.", 9), // off-chain injection
		}}
		pruneAnswerToChain(msg, "www.example.com.", protocol.TypeA)
		if len(msg.Answers) != 2 {
			t.Fatalf("expected 2 kept (CNAME + target A), got %d (%v)", len(msg.Answers), owners(msg))
		}
		for _, rr := range msg.Answers {
			if rr.Name.String() == "evil.example.org." {
				t.Error("off-chain injected record survived pruning")
			}
		}
	})

	t.Run("DNAME subtree preserved", func(t *testing.T) {
		msg := &protocol.Message{Answers: []*protocol.ResourceRecord{
			{Name: mkName(t, "old.example.com."), Type: protocol.TypeDNAME, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataDNAME{DName: mkName(t, "new.example.com.")}},
			cnameRR(t, "host.old.example.com.", "host.new.example.com."),
			aRR(t, "host.new.example.com.", 3),
		}}
		pruneAnswerToChain(msg, "host.old.example.com.", protocol.TypeA)
		if len(msg.Answers) != 3 {
			t.Errorf("DNAME chain pruned to %d, want 3 (%v)", len(msg.Answers), owners(msg))
		}
	})
}
