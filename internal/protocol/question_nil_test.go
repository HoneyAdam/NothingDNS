package protocol

import "testing"

func TestQuestionNilReceiverMatchersSafe(t *testing.T) {
	var q *Question

	if q.IsEDNS() {
		t.Fatal("nil Question IsEDNS() = true, want false")
	}
	if q.IsClassANY() {
		t.Fatal("nil Question IsClassANY() = true, want false")
	}
	if q.MatchesType(TypeA) {
		t.Fatal("nil Question MatchesType(TypeA) = true, want false")
	}
	if q.MatchesClass(ClassIN) {
		t.Fatal("nil Question MatchesClass(ClassIN) = true, want false")
	}
}
