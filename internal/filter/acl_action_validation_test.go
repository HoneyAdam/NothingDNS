package filter

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

// TestNewACLChecker_RejectsUnknownAction is a regression test: a mistyped ACL
// action (e.g. "block") used to compile cleanly, match, and do nothing — the
// query was then permitted by the default policy (silent fail-open). Unknown
// actions must now be rejected at compile time.
func TestNewACLChecker_RejectsUnknownAction(t *testing.T) {
	badActions := []string{"block", "reject", "drop", "permit", "xyz"}
	for _, action := range badActions {
		rules := []config.ACLRule{{
			Name:     "test",
			Action:   action,
			Networks: []string{"10.0.0.0/8"},
		}}
		if _, err := NewACLChecker(rules, false); err == nil {
			t.Errorf("NewACLChecker accepted unknown action %q, want error (silent fail-open)", action)
		}
	}
}

func TestNewACLChecker_AcceptsValidActions(t *testing.T) {
	rules := []config.ACLRule{
		{Name: "a", Action: "allow", Networks: []string{"10.0.0.0/8"}},
		{Name: "d", Action: "DENY", Networks: []string{"192.168.0.0/16"}}, // case-insensitive
		{Name: "r", Action: "redirect", Redirect: "blocked.example.", Networks: []string{"172.16.0.0/12"}},
	}
	if _, err := NewACLChecker(rules, false); err != nil {
		t.Fatalf("NewACLChecker rejected valid rules: %v", err)
	}
}

func TestNewACLChecker_RedirectRequiresTarget(t *testing.T) {
	rules := []config.ACLRule{{Name: "r", Action: "redirect", Networks: []string{"10.0.0.0/8"}}}
	_, err := NewACLChecker(rules, false)
	if err == nil || !strings.Contains(err.Error(), "redirect target") {
		t.Fatalf("expected redirect-target error, got %v", err)
	}
}

func TestUpdateRules_RejectsUnknownAction(t *testing.T) {
	c, err := NewACLChecker([]config.ACLRule{{Name: "a", Action: "allow", Networks: []string{"10.0.0.0/8"}}}, false)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	err = c.UpdateRules([]config.ACLRule{{Name: "bad", Action: "block", Networks: []string{"10.0.0.0/8"}}})
	if err == nil {
		t.Fatal("UpdateRules accepted unknown action, want error")
	}
}
